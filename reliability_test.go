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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestReliabilityRequestCancellationReachesDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	cancel()
	h := Handler{HideIP: true, aclRules: []aclRule{&aclAllRule{allow: true}}}
	h.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
			t.Error("cancelled request still dialing")
			return nil, errors.New("test dial timed out")
		}
	}
	r := (&http.Request{Method: "CONNECT", Host: "192.0.2.1:443", URL: &url.URL{Host: "192.0.2.1:443"}, ProtoMajor: 2, Header: make(http.Header), Body: http.NoBody}).WithContext(ctx)
	if err := h.ServeHTTP(httptest.NewRecorder(), r, nil); err == nil {
		t.Fatal("cancelled dial unexpectedly succeeded")
	}
}

type failedUpload struct{ err error }

func (r failedUpload) Read([]byte) (int, error) { return 0, r.err }
func (r failedUpload) Close() error             { return nil }

func TestReliabilityUploadErrorReleasesTunnel(t *testing.T) {
	target, origin := net.Pipe()
	defer origin.Close()
	defer target.Close()
	want := errors.New("client stream reset")
	done := make(chan error, 1)
	go func() { done <- dualStream(target, failedUpload{want}, io.Discard, false) }()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want upload error", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("upload failed but target read remains blocked")
		target.Close()
		<-done
	}
}

func TestReliabilityHalfClosePreservesResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, err := io.ReadAll(c)
		if err == nil && string(b) != "request" {
			err = errors.New("wrong upload")
		}
		if err == nil {
			_, err = c.Write([]byte("response after EOF"))
		}
		serverDone <- err
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var out bytes.Buffer
	if err := dualStream(c, io.NopCloser(bytes.NewBufferString("request")), &out, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "response after EOF" {
		t.Fatalf("response truncated: %q", out.String())
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestReliabilityPaddingFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		want string
		err  error
	}{
		{"empty padded frame", []byte{0, 0, 2, 99, 99, 0, 1, 0, 'x'}, "x", nil},
		{"truncated header", []byte{0}, "", io.ErrUnexpectedEOF},
		{"truncated payload", []byte{0, 2, 0, 'x'}, "x", io.ErrUnexpectedEOF},
		{"truncated padding", []byte{0, 1, 2, 'x', 99}, "x", io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := flushingIoCopy(&out, bytes.NewReader(tc.wire), make([]byte, 65536), RemovePadding)
			if !errors.Is(err, tc.err) || out.String() != tc.want {
				t.Fatalf("got (%q, %v), want (%q, %v)", out.String(), err, tc.want, tc.err)
			}
		})
	}
	for _, n := range []int{1, 65536, 700000} {
		input := bytes.Repeat([]byte("x"), n)
		var wire, output bytes.Buffer
		if _, err := flushingIoCopy(&wire, bytes.NewReader(input), make([]byte, 65536), AddPadding); err != nil {
			t.Fatal(err)
		}
		if _, err := flushingIoCopy(&output, &wire, make([]byte, 65536), RemovePadding); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, output.Bytes()) {
			t.Fatalf("padding roundtrip changed %d bytes", n)
		}
	}
}
