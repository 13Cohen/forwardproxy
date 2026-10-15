package forwardproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

type observationKey struct{}

// Request-local: DNS/dial fields are owned by the handler, each stream owns its
// own statistics. finish is called only after both stream goroutines have joined.
// Never emit addresses, credentials, payloads or per-chunk log events here.
type tunnelObservation struct {
	fields          *caddyhttp.ExtraLogFields
	start           time.Time
	id              string
	stage           string
	connection      *caddyhttp.ProxyEvidence
	responseFlushMS float64
	h2StreamID      uint32
	dnsMS           float64
	dnsObserved     bool
	candidates      int
	attempts        int
	upload          streamObservation
	download        streamObservation
}

type streamObservation struct {
	start            time.Time
	written          int64
	firstReadMS      float64
	readSeen         bool
	maxReadMS        float64
	maxWriteMS       float64
	maxFlushMS       float64
	maxReadStartMS   float64
	maxWriteStartMS  float64
	maxFlushStartMS  float64
	requestStart     time.Time
	connection       *caddyhttp.ProxyEvidence
	trace, direction string
}

func observation(ctx context.Context) *tunnelObservation {
	o, _ := ctx.Value(observationKey{}).(*tunnelObservation)
	return o
}

func newObservation(ctx context.Context) *tunnelObservation {
	fields, ok := ctx.Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields)
	if !ok || fields == nil {
		return nil
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil
	}
	o := &tunnelObservation{fields: fields, start: time.Now(), id: hex.EncodeToString(id[:]), stage: "response", connection: caddyhttp.EnableProxyEvidence(ctx)}
	o.h2StreamID = http2.ObservationStreamID(ctx)
	o.upload.requestStart, o.download.requestStart = o.start, o.start
	o.upload.connection, o.download.connection = o.connection, o.connection
	o.upload.trace, o.download.trace = o.id, o.id
	o.upload.direction, o.download.direction = "upload", "download"
	return o
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// A typed chain keeps direction and operation without parsing OS error prose.
type copyFailure struct {
	operation string
	err       error
}

func (e *copyFailure) Error() string { return e.operation + ": " + e.err.Error() }
func (e *copyFailure) Unwrap() error { return e.err }

type streamFailure struct {
	direction string
	err       error
}

func (e *streamFailure) Error() string { return e.direction + ": " + e.err.Error() }
func (e *streamFailure) Unwrap() error { return e.err }

func errorClass(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, syscall.ECONNRESET):
		return "peer_reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken_pipe"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "address_unavailable"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network_unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host_unreachable"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, io.ErrShortWrite):
		return "short_write"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "closed"
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "timeout"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	// Go net/http's internal HTTP2 stream error type is not exported. Preserve
	// ambiguity: a stream error is not necessarily an intentional cancellation.
	if strings.Contains(err.Error(), "stream error:") {
		return "stream_error"
	}
	return "other"
}

func (o *tunnelObservation) finish(ctx context.Context, err error) {
	if o == nil {
		return
	}
	// ExtraLogFields is not safe for concurrent mutation. Only the handler writes.
	for _, field := range o.logFields(ctx, err) {
		o.fields.Set(field)
	}
}

func (o *tunnelObservation) logFields(ctx context.Context, err error) []zap.Field {
	class, side := errorClass(err), "none"
	if o.stage == "response" && err != nil {
		side = "client_response_flush"
	}
	var stream *streamFailure
	var operation *copyFailure
	if errors.As(err, &stream) {
		side = stream.direction
		if errors.As(err, &operation) {
			if stream.direction == "upload" {
				if operation.operation == "read" {
					side = "client_read"
				} else {
					side = "target_write"
				}
			} else {
				if operation.operation == "read" {
					side = "target_read"
				} else {
					side = "client_" + operation.operation
				}
			}
		}
	}
	end := "error"
	if err == nil {
		end = "clean_eof"
	}
	if class == "canceled" || (class == "closed" && ctx.Err() == context.Canceled) {
		end = "request_canceled"
	}
	fields := []zap.Field{
		zap.Uint32("proxy_h2_stream_id", o.h2StreamID), zap.Int("proxy_diag_version", 3), zap.String("proxy_trace_id", o.id),
		zap.Float64("proxy_started_unix_ms", float64(o.start.UnixNano())/1e6),
		zap.String("proxy_connection_id", o.connection.ID()),
		zap.Float64("proxy_response_flush_ms", o.responseFlushMS),
		zap.String("proxy_end_reason", end), zap.String("proxy_error_class", class),
		zap.String("proxy_error_side", side), zap.String("proxy_stage", o.stage),
		zap.Bool("proxy_request_canceled", ctx.Err() == context.Canceled),
		zap.Float64("proxy_total_ms", milliseconds(time.Since(o.start))),
		zap.Int("proxy_dial_candidates", o.candidates), zap.Int("proxy_dial_attempts", o.attempts),
	}
	if o.dnsObserved {
		fields = append(fields, zap.Float64("proxy_dns_ms", o.dnsMS))
	}
	for _, item := range []struct {
		name string
		stat *streamObservation
	}{{"upload", &o.upload}, {"download", &o.download}} {
		s := item.stat
		if s.start.IsZero() {
			continue
		}
		prefix := "proxy_" + item.name + "_"
		fields = append(fields, zap.Int64(prefix+"written_bytes", s.written),
			zap.Float64(prefix+"max_read_block_ms", s.maxReadMS),
			zap.Float64(prefix+"max_write_block_ms", s.maxWriteMS),
			zap.Float64(prefix+"max_flush_block_ms", s.maxFlushMS),
			zap.Float64(prefix+"max_read_start_ms", s.maxReadStartMS),
			zap.Float64(prefix+"max_write_start_ms", s.maxWriteStartMS),
			zap.Float64(prefix+"max_flush_start_ms", s.maxFlushStartMS))
		if s.readSeen {
			fields = append(fields, zap.Float64(prefix+"first_read_ms", s.firstReadMS))
		}
	}
	return fields
}
