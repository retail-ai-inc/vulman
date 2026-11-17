// Package workflow provides cancellable checkpoints between units of sync work.
package workflow

import (
	"context"
	"sync"
	"time"
)

type contextKey struct{}

type Control struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	paused    bool
	stopped   bool
	changed   chan struct{}
	timer     *time.Timer
	remaining time.Duration
	since     time.Time
	onPaused  func()
}

// New counts only unpaused time against the run's total budget.
func New(parent context.Context, budget time.Duration, onPaused func()) *Control {
	ctx, cancel := context.WithCancel(parent)
	c := &Control{cancel: cancel, changed: make(chan struct{}), remaining: budget, since: time.Now(), onPaused: onPaused}
	c.ctx = context.WithValue(ctx, contextKey{}, c)
	c.arm()
	return c
}

func (c *Control) Context() context.Context { return c.ctx }
func (c *Control) arm() {
	c.timer = time.AfterFunc(c.remaining, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.paused && time.Since(c.since) >= c.remaining {
			c.cancel()
		}
	})
}
func (c *Control) signal() { close(c.changed); c.changed = make(chan struct{}) }

func (c *Control) Pause() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused || c.stopped || c.ctx.Err() != nil {
		return
	}
	c.remaining -= time.Since(c.since)
	c.timer.Stop()
	c.paused = true
	c.signal()
}
func (c *Control) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused || c.stopped || c.ctx.Err() != nil {
		return
	}
	c.paused = false
	c.since = time.Now()
	c.arm()
	c.signal()
}
func (c *Control) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true
	c.timer.Stop()
	c.cancel()
	c.signal()
}
func (c *Control) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer.Stop()
	c.cancel()
}
func (c *Control) Stopped() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.stopped }

func control(ctx context.Context) *Control { c, _ := ctx.Value(contextKey{}).(*Control); return c }
func Paused(ctx context.Context) bool {
	if c := control(ctx); c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.paused
	}
	return false
}

// Changes allows shared-query waiters to leave a paused owner without cancelling it.
func Changes(ctx context.Context) <-chan struct{} {
	if c := control(ctx); c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.changed
	}
	return nil
}

func Wait(ctx context.Context) error {
	c := control(ctx)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c == nil {
			return nil
		}
		c.mu.Lock()
		paused, changed, acknowledge := c.paused, c.changed, c.onPaused
		c.mu.Unlock()
		if !paused {
			return nil
		}
		if acknowledge != nil {
			acknowledge()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
