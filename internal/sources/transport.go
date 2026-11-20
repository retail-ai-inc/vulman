package sources

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/workflow"
)

type requestKey struct{}
type requestInfo struct {
	kind, key string
	reports   []func(model.SyncProgress)
}

func withRequest(ctx context.Context, kind, key string, reports []func(model.SyncProgress)) context.Context {
	return context.WithValue(ctx, requestKey{}, requestInfo{kind, key, reports})
}

type providerGate struct {
	slot chan struct{}
	mu   sync.Mutex
	next time.Time
}

type cooldownError struct{ delay time.Duration }

func (e cooldownError) PublicMessage() apperror.Message {
	return apperror.Newf("provider_cooldown", "upstream is cooling down; try again in %d seconds", ceilSeconds(e.delay)).PublicMessage()
}

func (e cooldownError) Error() string {
	return fmt.Sprintf("upstream is cooling down; try again in %d seconds", ceilSeconds(e.delay))
}

func ceilSeconds(d time.Duration) int {
	seconds := d / time.Second
	if d%time.Second > 0 {
		seconds++
	}
	return int(seconds)
}

func wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) gate(kind string) *providerGate {
	c.gatesMu.Lock()
	defer c.gatesMu.Unlock()

	g := c.gates[kind]

	if g == nil {
		g = &providerGate{slot: make(chan struct{}, 1)}
		c.gates[kind] = g
	}
	return g
}

func (c *Client) gap(kind, key string) time.Duration {
	if d, ok := c.gapOverride[kind]; ok {
		return d
	}

	switch kind {
	case "nvd":
		if key != "" {
			return 650 * time.Millisecond
		}
		return 6100 * time.Millisecond
	case "osv":
		return 200 * time.Millisecond
	default:
		return 300 * time.Millisecond
	}
}

func (c *Client) acquire(ctx context.Context, info requestInfo) (func(), error) {
	g := c.gate(info.kind)
	select {
	case g.slot <- struct{}{}:
	default:
		notify(info.reports, model.SyncProgress{Phase: "queued"})
		select {
		case g.slot <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	release := func() { <-g.slot }
	g.mu.Lock()
	delay := time.Until(g.next)
	g.mu.Unlock()

	if delay > 0 {
		notify(info.reports, model.SyncProgress{Phase: "waiting", WaitSeconds: ceilSeconds(delay)})
		if delay > 30*time.Second {
			release()
			return nil, cooldownError{delay}
		}

		if err := wait(ctx, delay); err != nil {
			release()
			return nil, err
		}
	}

	if info.kind == "nvd" {
		if _, overridden := c.gapOverride["nvd"]; !overridden {
			if err := c.pace(ctx, info.key, info.reports...); err != nil {
				release()
				return nil, err
			}
		}
	}
	g.mu.Lock()
	g.next = time.Now().Add(c.gap(info.kind, info.key))
	g.mu.Unlock()
	notify(info.reports, model.SyncProgress{Phase: "request"})
	return release, nil
}

func retryAfter(header string) time.Duration {
	if secs, err := strconv.Atoi(header); err == nil && secs >= 0 {
		if uint64(secs) > uint64((1<<63-1)/int64(time.Second)) {
			return time.Duration(1<<63 - 1)
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(header); err == nil {
		if d := time.Until(at); d > 0 {
			return d
		}
	}
	return 0
}

func (c *Client) cooldown(kind string, d time.Duration) {
	g := c.gate(kind)
	g.mu.Lock()

	if until := time.Now().Add(d); until.After(g.next) {
		g.next = until
	}

	g.mu.Unlock()
}

func retryable(status int, err error) bool {
	var network net.Error
	return status == 429 || status == 500 || status == 502 || status == 503 || status == 504 || (status == 0 && errors.As(err, &network)) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (c *Client) backoff(attempt int, header string) time.Duration {
	delay := c.retryBase * time.Duration(1<<attempt)

	if delay <= 0 {
		delay = time.Second
	}

	if jitter, err := rand.Int(rand.Reader, big.NewInt(int64(delay/4)+1)); err == nil {
		delay += time.Duration(jitter.Int64())
	}

	if suggested := retryAfter(header); suggested > delay {
		delay = suggested
	}

	return delay
}

func (c *Client) request(ctx context.Context, method, endpoint string, payload any, headers map[string]string, out any) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}

	info, _ := ctx.Value(requestKey{}).(requestInfo)
	if info.kind == "" {
		info.kind = "upstream"
	}

	for attempt := 0; attempt < 3; attempt++ {
		if err = ctx.Err(); err != nil {
			return err
		}

		var data []byte
		status := 0
		retryHeader := ""
		var delay time.Duration

		err = func() (attemptErr error) {
			var release func()
			for {
				if e := workflow.Wait(ctx); e != nil {
					return e
				}

				var e error
				release, e = c.acquire(ctx, info)
				if e != nil {
					return e
				}

				if !workflow.Paused(ctx) {
					break
				}

				// A paused run must not hold the provider's shared request slot.
				release()
			}
			defer func() {
				if ctx.Err() == nil && retryable(status, attemptErr) {
					delay = c.backoff(attempt, retryHeader)
					c.cooldown(info.kind, delay)
				}
				release()
			}()

			req, e := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
			if e != nil {
				return e
			}

			req.Header.Set("User-Agent", "Vulman/0.1 (local vulnerability management)")
			req.Header.Set("Accept", "application/json")

			if payload != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			for k, v := range headers {
				req.Header.Set(k, v)
			}

			resp, e := c.HTTP.Do(req)
			if e != nil {
				return e
			}

			// Explicitly discarding the error
			defer func() { _ = resp.Body.Close() }()

			status = resp.StatusCode
			retryHeader = resp.Header.Get("Retry-After")
			if status != 200 {
				return apperror.Newf("upstream_http", "upstream returned HTTP %d", status)
			}

			data, e = io.ReadAll(io.LimitReader(resp.Body, 40<<20))
			if e != nil {
				return e
			}

			if len(data) >= 40<<20 {
				return apperror.New("upstream_response_exceeds_limit", "upstream response exceeds limit")
			}
			return nil
		}()

		if err == nil {
			return json.Unmarshal(data, out)
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if !retryable(status, err) {
			return err
		}

		notify(info.reports, model.SyncProgress{Phase: "retry", WaitSeconds: ceilSeconds(delay), Item: fmt.Sprintf("HTTP %d", status)})
		if attempt == 2 || delay > 30*time.Second {
			return err
		}
	}

	return err
}
