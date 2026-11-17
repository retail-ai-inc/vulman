package workflow

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPauseResumeAndStopWakeCheckpoints(t *testing.T) {
	ack := make(chan struct{}, 1)
	c := New(context.Background(), time.Minute, func() {
		select {
		case ack <- struct{}{}:
		default:
		}
	})
	defer c.Close()
	c.Pause()
	done := make(chan error, 1)
	go func() { done <- Wait(c.Context()) }()
	select {
	case <-ack:
	case <-time.After(time.Second):
		t.Fatal("pause not acknowledged")
	}
	select {
	case err := <-done:
		t.Fatalf("paused checkpoint returned early: %v", err)
	default:
	}
	c.Resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resume did not wake checkpoint")
	}
	c.Pause()
	go func() { done <- Wait(c.Context()) }()
	c.Stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not cancel paused checkpoint")
	}
	c.Resume()
	if !c.Stopped() || c.Context().Err() == nil {
		t.Fatal("stopped workflow resumed")
	}
}

func TestPausedTimeDoesNotConsumeBudget(t *testing.T) {
	c := New(context.Background(), 100*time.Millisecond, nil)
	defer c.Close()
	c.Pause()
	time.Sleep(150 * time.Millisecond)
	if c.Context().Err() != nil {
		t.Fatal("paused budget expired")
	}
	c.Resume()
	select {
	case <-c.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("active budget did not expire")
	}
}

func TestParentCancellationStopsPausedRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := New(ctx, time.Minute, nil)
	defer c.Close()
	c.Pause()
	cancel()
	if !errors.Is(Wait(c.Context()), context.Canceled) {
		t.Fatal("paused run ignored app shutdown")
	}
}
