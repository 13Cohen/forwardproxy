package forwardproxy

import (
	"context"
	"errors"
	"net"
	"time"
)

// dialAllowed races only numeric addresses already checked against the ACL.
// At most two attempts are live. A stalled first address must not hold up a
// working alternative for the entire dial timeout. There is no second DNS lookup.
func (h Handler) dialAllowed(ctx context.Context, network, port string, ips []net.IP) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result) // unbuffered: every unclaimed connection is closed
	next, active := 0, 0
	start := func() {
		ip := ips[next]
		remaining := len(ips) - next
		next++
		active++
		go func() {
			attemptCtx := ctx
			stop := func() {}
			if deadline, ok := ctx.Deadline(); ok {
				// Share the remaining budget, so two unreachable addresses cannot
				// occupy both slots until the whole request expires.
				budget := time.Until(deadline) / time.Duration(remaining)
				if budget < 250*time.Millisecond {
					budget = 250 * time.Millisecond
				}
				attemptCtx, stop = context.WithTimeout(ctx, budget)
			}
			defer stop()
			conn, err := h.dialContext(attemptCtx, network, net.JoinHostPort(ip.String(), port))
			if err != nil && conn != nil {
				conn.Close()
				conn = nil
			}
			if err == nil && conn == nil {
				err = errors.New("dialer returned no connection")
			}
			select {
			case results <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no dial candidates")
	}
	start()
	delay := 250 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline)/4 < delay {
		delay = time.Until(deadline) / 4
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	fallback := false
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			fallback = true
			if next < len(ips) && active < 2 {
				start()
			}
		case r := <-results:
			active--
			if err := ctx.Err(); err != nil {
				if r.conn != nil {
					r.conn.Close()
				}
				return nil, err
			}
			if r.err == nil {
				return r.conn, nil
			}
			lastErr = r.err
			if next < len(ips) && (active == 0 || fallback) {
				start()
			}
			if active == 0 {
				return nil, lastErr
			}
		}
	}
}
