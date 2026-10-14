package forwardproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http2"
)

// Real TLS + HTTP/2 CONNECT: bulk data, half-closes and reset storms share
// a client connection. A reset must release the target without killing peers.
func TestReliabilityHTTP2Isolation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var workers sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				cmd := make([]byte, 1)
				if _, err := io.ReadFull(c, cmd); err != nil {
					return
				}
				if cmd[0] == 'B' {
					buf := bytes.Repeat([]byte("b"), 32768)
					for range 256 {
						if _, err := c.Write(buf); err != nil {
							return
						}
						time.Sleep(time.Millisecond)
					}
				} else {
					b, err := io.ReadAll(c)
					if err == nil {
						c.Write(b)
					}
				}
			}()
		}
	}()
	h := Handler{HideIP: true, aclRules: []aclRule{&aclAllRule{allow: true}}, AuthCredentials: [][]byte{EncodeAuthCredentials("test", "pass")}, dialContext: (&net.Dialer{}).DialContext}
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
		r = r.WithContext(ctx)
		h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { w.WriteHeader(404); return nil }))
	}))
	proxy.EnableHTTP2 = true
	if err := http2.ConfigureServer(proxy.Config, &http2.Server{MaxConcurrentStreams: 512, ReadIdleTimeout: 30 * time.Second, PingTimeout: 15 * time.Second, WriteByteTimeout: 60 * time.Second}); err != nil {
		t.Fatal(err)
	}
	proxy.StartTLS()
	defer proxy.Close()
	pool := x509.NewCertPool()
	pool.AddCert(proxy.Certificate())
	conn, err := tls.Dial("tcp", proxy.Listener.Addr().String(), &tls.Config{RootCAs: pool, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := func(ctx context.Context, body io.ReadCloser) (*http.Response, error) {
		r := (&http.Request{Method: "CONNECT", Host: ln.Addr().String(), URL: &url.URL{Host: ln.Addr().String()}, Header: make(http.Header), Body: body}).WithContext(ctx)
		r.Header.Set("Proxy-Authorization", "Basic dGVzdDpwYXNz")
		return cc.RoundTrip(r)
	}
	bulk, err := request(ctx, io.NopCloser(bytes.NewBufferString("B")))
	if err != nil {
		t.Fatal(err)
	}
	bulkDone := make(chan error, 1)
	go func() {
		defer bulk.Body.Close()
		n, err := io.Copy(io.Discard, bulk.Body)
		if err == nil && n != 8*1024*1024 {
			err = fmt.Errorf("bulk truncated: %d", n)
		}
		bulkDone <- err
	}()
	errs := make(chan error, 48)
	start := time.Now()
	for i := range 48 {
		go func(i int) {
			payload := fmt.Sprintf("echo-%d", i)
			resp, err := request(ctx, io.NopCloser(bytes.NewBufferString("E"+payload)))
			if err == nil {
				var b []byte
				b, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err == nil && string(b) != payload {
					err = fmt.Errorf("echo %d truncated", i)
				}
			}
			errs <- err
		}(i)
	}
	for range 48 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("48 small tunnels alongside 8 MiB download completed in %v", time.Since(start))
	// Reset idle uploads on the same connection, then prove it still works.
	for range 32 {
		resetCtx, reset := context.WithCancel(ctx)
		reader, writer := io.Pipe()
		resp, err := request(resetCtx, reader)
		reset()
		writer.Close()
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	resp, err := request(ctx, io.NopCloser(bytes.NewBufferString("Estill-alive")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != "still-alive" {
		t.Fatalf("reset poisoned shared connection: %q %v", b, err)
	}
	if err := <-bulkDone; err != nil {
		t.Fatal(err)
	}
	cc.Close()
	ln.Close()
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("origin connections leaked after cancellation")
	}
}
