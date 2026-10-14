package forwardproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestReliabilityFallbackAndLoserCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	loserDone := make(chan struct{})
	winner, peer := net.Pipe()
	defer peer.Close()
	h := Handler{dialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		if addr == "192.0.2.1:443" {
			<-ctx.Done()
			close(loserDone)
			return nil, ctx.Err()
		}
		return winner, nil
	}}
	start := time.Now()
	c, err := h.dialAllowed(ctx, "tcp", "443", []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("fallback took %v", elapsed)
	}
	select {
	case <-loserDone:
	case <-time.After(time.Second):
		t.Fatal("loser not cancelled")
	}
	t.Logf("working fallback selected in %v", time.Since(start))
}

func TestReliabilityDialConcurrencyAndDeadline(t *testing.T) {
	var active, peak, attempts atomic.Int32
	h := Handler{dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		attempts.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3"), net.ParseIP("192.0.2.4")}
	start := time.Now()
	_, err := h.dialAllowed(ctx, "tcp", "443", ips)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("deadline failed: %v", err)
	}
	if peak.Load() > 2 || attempts.Load() != 4 {
		t.Fatalf("peak=%d attempts=%d", peak.Load(), attempts.Load())
	}
}

func TestReliabilityDNSCancellation(t *testing.T) {
	h := Handler{DialTimeout: caddy.Duration(80 * time.Millisecond), aclRules: []aclRule{&aclAllRule{allow: true}}, lookupIP: func(ctx context.Context, _, _ string) ([]net.IP, error) { <-ctx.Done(); return nil, ctx.Err() }}
	start := time.Now()
	_, err := h.dialContextCheckACL(context.Background(), "tcp", "example.test:443")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("DNS escaped total deadline: %v", err)
	}
}

func TestReliabilityACLBeforeRace(t *testing.T) {
	deny, _ := newACLRule("127.0.0.0/8", false)
	var dialed atomic.Int32
	h := Handler{DialTimeout: caddy.Duration(time.Second), aclRules: []aclRule{deny, &aclAllRule{allow: true}}, lookupIP: func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.0.2.1")}, nil
	}}
	winner, peer := net.Pipe()
	defer peer.Close()
	h.dialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed.Add(1)
		if addr != "192.0.2.1:443" {
			t.Errorf("ACL bypass: %s", addr)
		}
		return winner, nil
	}
	c, err := h.dialContextCheckACL(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if dialed.Load() != 1 {
		t.Fatalf("dial count %d", dialed.Load())
	}
	h.aclRules = []aclRule{&aclAllRule{allow: false}}
	_, err = h.dialContextCheckACL(context.Background(), "tcp", "example.test:443")
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden || dialed.Load() != 1 {
		t.Fatalf("denied IP was dialed: %v", err)
	}
	h.aclRules = []aclRule{&aclAllRule{allow: true}}
	h.dialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	_, err = h.dialContextCheckACL(context.Background(), "tcp", "example.test:443")
	if !errors.As(err, &he) || he.StatusCode != http.StatusBadGateway {
		t.Fatalf("dial failure mislabeled ACL denial: %v", err)
	}
}
