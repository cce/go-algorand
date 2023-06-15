package scorelimiter

import (
	"context"
	"testing"
	"time"

	"github.com/algorand/go-algorand/logging"
)

type testPeer struct {
	ip string
}

func (p testPeer) GetIP() (string, error) { return p.ip, nil }

type testMessage struct {
	receivedFrom peerID
}

func (m testMessage) ReceivedFrom() peerID { return m.receivedFrom }
func (m testMessage) GetTopic() string     { return "" }

func TestPeerGater(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peerAip := "1.2.3.4"
	peerA := testPeer{ip: peerAip}

	params := NewPeerGaterParams(.1, .9, .999)
	err := params.validate()
	if err != nil {
		t.Fatal(err)
	}

	pg := newPeerGater(ctx, logging.Base(), nil, params)

	pg.AddPeer(peerA)

	status := pg.AcceptFrom(peerA)
	if status != AcceptAll {
		t.Fatal("expected AcceptAll")
	}

	msg := testMessage{receivedFrom: peerA}

	pg.ValidateMessage(msg)
	status = pg.AcceptFrom(peerA)
	if status != AcceptAll {
		t.Fatal("expected AcceptAll")
	}

	pg.RejectMessage(msg, RejectValidationQueueFull)
	status = pg.AcceptFrom(peerA)
	if status != AcceptAll {
		t.Fatal("expected AcceptAll")
	}

	pg.RejectMessage(msg, RejectValidationThrottled)
	status = pg.AcceptFrom(peerA)
	if status != AcceptAll {
		t.Fatal("expected AcceptAll")
	}

	for i := 0; i < 100; i++ {
		pg.RejectMessage(msg, RejectValidationIgnored)
		pg.RejectMessage(msg, RejectValidationFailed)
	}

	accepted := false
	for i := 0; !accepted && i < 1000; i++ {
		status = pg.AcceptFrom(peerA)
		if status == AcceptControl {
			accepted = true
		}
	}
	if !accepted {
		t.Fatal("expected AcceptControl")
	}

	for i := 0; i < 100; i++ {
		pg.DeliverMessage(msg)
	}

	accepted = false
	for i := 0; !accepted && i < 1000; i++ {
		status = pg.AcceptFrom(peerA)
		if status == AcceptAll {
			accepted = true
		}
	}
	if !accepted {
		t.Fatal("expected to accept at least once")
	}

	for i := 0; i < 100; i++ {
		pg.decayStats()
	}

	status = pg.AcceptFrom(peerA)
	if status != AcceptAll {
		t.Fatal("expected AcceptAll")
	}

	pg.RemovePeer(peerA)
	pg.Lock()
	_, ok := pg.peerStats[peerA]
	pg.Unlock()
	if ok {
		t.Fatal("still have a stat record for peerA")
	}

	pg.Lock()
	_, ok = pg.ipStats[peerAip]
	pg.Unlock()
	if !ok {
		t.Fatal("expected to still have a stat record for peerA's ip")
	}

	pg.Lock()
	pg.ipStats[peerAip].expire = time.Now()
	pg.Unlock()

	time.Sleep(2 * time.Second)

	pg.Lock()
	_, ok = pg.ipStats["1.2.3.4"]
	pg.Unlock()
	if ok {
		t.Fatal("still have a stat record for peerA's ip")
	}
}
