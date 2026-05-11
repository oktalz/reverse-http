package h2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSendCreditReserveAvailable: when both windows have credit, Reserve
// returns the requested amount and decrements both.
func TestSendCreditReserveAvailable(t *testing.T) {
	var sw int32 = 1000
	sc := SendCredit{ConnSendWindow: 500, PeerInitWindow: DefaultInitialWindow}

	got, dead := sc.Reserve(&sw, 200)
	if dead {
		t.Fatal("unexpected dead")
	}
	if got != 200 {
		t.Fatalf("got %d, want 200", got)
	}
	if sc.ConnSendWindow != 300 {
		t.Fatalf("conn window now %d, want 300", sc.ConnSendWindow)
	}
	if sw != 800 {
		t.Fatalf("stream window now %d, want 800", sw)
	}
}

// TestSendCreditReserveCappedByMin: Reserve returns at most the smaller of
// the two windows even when the caller asks for more.
func TestSendCreditReserveCappedByMin(t *testing.T) {
	var sw int32 = 50
	sc := SendCredit{ConnSendWindow: 1000}

	got, _ := sc.Reserve(&sw, 200)
	if got != 50 {
		t.Fatalf("got %d, want 50 (stream window cap)", got)
	}

	sw = 1000
	sc.ConnSendWindow = 30
	got, _ = sc.Reserve(&sw, 200)
	if got != 30 {
		t.Fatalf("got %d, want 30 (conn window cap)", got)
	}
}

// TestSendCreditBlocksUntilCredit: with zero credit on both windows, Reserve
// blocks; AddConn wakes it.
func TestSendCreditBlocksUntilCredit(t *testing.T) {
	var sw int32
	sc := SendCredit{ConnSendWindow: 0}

	type res struct {
		got  int32
		dead bool
	}
	done := make(chan res, 1)
	go func() {
		got, dead := sc.Reserve(&sw, 100)
		done <- res{got, dead}
	}()

	select {
	case r := <-done:
		t.Fatalf("Reserve returned early: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}

	sc.AddConn(500)
	select {
	case r := <-done:
		t.Fatalf("Reserve returned with stream window still 0: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}

	sc.AddStream(&sw, 50)
	select {
	case r := <-done:
		if r.dead || r.got != 50 {
			t.Fatalf("got %+v, want got=50 dead=false", r)
		}
	case <-time.After(time.Second):
		t.Fatal("Reserve did not unblock after AddStream")
	}
}

// TestSendCreditMarkDead releases waiters with dead=true so a handler
// doesn't hang forever on a torn-down connection.
func TestSendCreditMarkDead(t *testing.T) {
	var sw int32
	sc := SendCredit{ConnSendWindow: 0}

	type res struct {
		got  int32
		dead bool
	}
	done := make(chan res, 2)
	for range 2 {
		go func() {
			got, dead := sc.Reserve(&sw, 100)
			done <- res{got, dead}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	sc.MarkDead()

	for i := range 2 {
		select {
		case r := <-done:
			if !r.dead || r.got != 0 {
				t.Fatalf("got %+v, want dead=true got=0", r)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiter %d not released by MarkDead", i)
		}
	}
}

// TestSendCreditApplyInitialWindowDelta: a peer SETTINGS frame changing
// SETTINGS_INITIAL_WINDOW_SIZE must shift every existing stream's send
// window by the delta (new - old), positive or negative.
func TestSendCreditApplyInitialWindowDelta(t *testing.T) {
	sw1 := int32(65535)
	sw2 := int32(40000)
	sc := SendCredit{ConnSendWindow: DefaultInitialWindow, PeerInitWindow: DefaultInitialWindow}

	sc.ApplyInitialWindowDelta(100000, []*int32{&sw1, &sw2})

	if want := int32(65535 + (100000 - 65535)); sw1 != want {
		t.Fatalf("sw1 = %d, want %d", sw1, want)
	}
	if want := int32(40000 + (100000 - 65535)); sw2 != want {
		t.Fatalf("sw2 = %d, want %d", sw2, want)
	}
	if sc.PeerInitWindow != 100000 {
		t.Fatalf("PeerInitWindow = %d, want 100000", sc.PeerInitWindow)
	}

	sc.ApplyInitialWindowDelta(10000, []*int32{&sw1, &sw2})
	if sw1 >= int32(100000) {
		t.Fatalf("sw1 not decremented: %d", sw1)
	}
}

// TestSendCreditConcurrent: many goroutines reserving from a shared pool
// distribute the credit without losing or double-counting bytes.
func TestSendCreditConcurrent(t *testing.T) {
	const writers = 10
	const perWriter = 100
	const chunk = 7

	var sw int32 = 100000
	sc := SendCredit{ConnSendWindow: 100000}

	var sum atomic.Int64
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range perWriter {
				got, dead := sc.Reserve(&sw, chunk)
				if dead {
					t.Error("unexpected dead")
					return
				}
				sum.Add(int64(got))
			}
		})
	}
	wg.Wait()

	want := int64(writers * perWriter * chunk)
	if sum.Load() != want {
		t.Fatalf("got %d, want %d", sum.Load(), want)
	}
	if got := int32(100000) - sc.ConnSendWindow; got != int32(want) {
		t.Fatalf("conn window consumed %d, want %d", got, want)
	}
	if got := int32(100000) - sw; got != int32(want) {
		t.Fatalf("stream window consumed %d, want %d", got, want)
	}
}
