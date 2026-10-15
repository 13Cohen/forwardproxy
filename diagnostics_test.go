package forwardproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zapcore"
)

type blockedUpload struct {
	done chan struct{}
	once sync.Once
}

func (r *blockedUpload) Read([]byte) (int, error) { <-r.done; return 0, io.ErrClosedPipe }
func (r *blockedUpload) Close() error             { r.once.Do(func() { close(r.done) }); return nil }

type resetTarget struct{ net.Conn }

func (resetTarget) Read([]byte) (int, error)    { return 0, syscall.ECONNRESET }
func (resetTarget) Write(p []byte) (int, error) { return len(p), nil }
func (resetTarget) Close() error                { return nil }

func TestDiagnosticsDownloadResetIsNotOverwrittenByCleanup(t *testing.T) {
	upload := &blockedUpload{done: make(chan struct{})}
	obs := &tunnelObservation{start: time.Now(), stage: "transfer"}
	done := make(chan error, 1)
	go func() { done <- dualStreamObserved(resetTarget{}, upload, io.Discard, false, obs) }()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("initiating reset lost: %v", err)
		}
		enc := zapcore.NewMapObjectEncoder()
		for _, field := range obs.logFields(context.Background(), err) {
			field.AddTo(enc)
		}
		if enc.Fields["proxy_error_side"] != "target_read" || enc.Fields["proxy_error_class"] != "peer_reset" {
			t.Fatalf("misattributed error: %#v", enc.Fields)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel cleanup blocked")
	}
}

func TestDiagnosticsDialFailureFieldsAndPrivacy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
		ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, new(caddyhttp.ExtraLogFields))
		var observed *tunnelObservation
		h := Handler{Diagnostics: enabled, HideIP: true, aclRules: []aclRule{&aclAllRule{allow: true}}}
		h.lookupIP = func(ctx context.Context, _, _ string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.8")}, nil
		}
		h.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			observed = observation(ctx)
			return nil, syscall.ECONNREFUSED
		}
		r := (&http.Request{Method: "CONNECT", Host: "private.example:443", URL: &url.URL{Host: "private.example:443"}, ProtoMajor: 2, Header: make(http.Header), Body: http.NoBody}).WithContext(ctx)
		err := h.ServeHTTP(httptest.NewRecorder(), r, nil)
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("wrong failure: %v", err)
		}
		if !enabled {
			if observed != nil {
				t.Fatal("diagnostics enabled by default")
			}
			continue
		}
		if observed == nil {
			t.Fatal("missing observation")
		}
		enc := zapcore.NewMapObjectEncoder()
		for _, field := range observed.logFields(ctx, err) {
			field.AddTo(enc)
		}
		if enc.Fields["proxy_error_class"] != "refused" || enc.Fields["proxy_stage"] != "dial" || observed.attempts != 1 || !observed.dnsObserved {
			t.Fatalf("missing dial diagnostics: %#v", enc.Fields)
		}
		if len(observed.id) != 32 {
			t.Fatal("missing random request identifier")
		}
		for _, value := range enc.Fields {
			if s, ok := value.(string); ok && (strings.Contains(s, "private.example") || strings.Contains(s, "192.0.2.8")) {
				t.Fatal("address copied into diagnostics")
			}
		}
	}
}

type slowWriter struct{ bytes.Buffer }

type failingResponseFlush struct{ *httptest.ResponseRecorder }

func (*failingResponseFlush) FlushError() error { return context.DeadlineExceeded }

func TestDiagnosticsInitialFlushPreservesCauseAndSkipsDial(t *testing.T) {
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, new(caddyhttp.ExtraLogFields))
	h := Handler{Diagnostics: true, HideIP: true, aclRules: []aclRule{&aclAllRule{allow: true}}}
	h.lookupIP = func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("dial path entered before response flush completed")
		return nil, nil
	}
	r := (&http.Request{Method: "CONNECT", Host: "example.invalid:443", URL: &url.URL{Host: "example.invalid:443"}, ProtoMajor: 2, Header: make(http.Header), Body: http.NoBody}).WithContext(ctx)
	err := h.ServeHTTP(&failingResponseFlush{httptest.NewRecorder()}, r, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush cause lost: %v", err)
	}
}

func (w *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(15 * time.Millisecond)
	return w.Buffer.Write(p)
}

func TestDiagnosticsMeasuresBlockingAndPreservesPadding(t *testing.T) {
	input := bytes.Repeat([]byte("secret payload"), 100)
	var wire slowWriter
	var stat streamObservation
	_, err := flushingIoCopyObserved(&wire, bytes.NewReader(input), make([]byte, 65536), AddPadding, &stat)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err = flushingIoCopy(&out, &wire, make([]byte, 65536), RemovePadding); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), input) {
		t.Fatal("diagnostics changed payload")
	}
	if stat.written <= int64(len(input)) || !stat.readSeen || stat.maxWriteMS < 10 {
		t.Fatalf("missing blocking/byte stats: %+v", stat)
	}
}

func TestDiagnosticsCaddyfileAndCanceledClassification(t *testing.T) {
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("forward_proxy {\n diagnostics\n}")); err != nil || !h.Diagnostics {
		t.Fatalf("diagnostics directive: %v", err)
	}
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("forward_proxy {\n diagnostics unexpected\n}")); err == nil {
		t.Fatal("unexpected argument accepted")
	}
	if errorClass(&streamFailure{"upload", &copyFailure{"read", context.Canceled}}) != "canceled" {
		t.Fatal("cancellation lost")
	}
	if errorClass(errors.New("stream error: stream ID 3; REFUSED_STREAM")) != "stream_error" {
		t.Fatal("HTTP2 stream error misclassified")
	}
}

func BenchmarkDiagnosticsCopy(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			payload, buf := make([]byte, 65536), make([]byte, 65536)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var stat *streamObservation
				if enabled {
					stat = new(streamObservation)
				}
				if _, err := flushingIoCopyObserved(io.Discard, bytes.NewReader(payload), buf, NoPadding, stat); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
