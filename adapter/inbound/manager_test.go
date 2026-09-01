package inbound

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func TestManagerCreateClosesInboundWhenStartFails(t *testing.T) {
	candidate := &startFailureInbound{}
	manager := NewManager(nil, &singleInboundRegistry{inbound: candidate}, nil)
	manager.started = true

	err := manager.Create(context.Background(), nil, nil, "test", "test", nil)
	if err == nil {
		t.Fatal("expected dynamic inbound start failure")
	}
	if candidate.closeCalls != 1 {
		t.Fatalf("candidate Close calls = %d, want 1", candidate.closeCalls)
	}
	if len(manager.Inbounds()) != 0 {
		t.Fatal("failed inbound was added to manager")
	}
}

type singleInboundRegistry struct {
	inbound adapter.Inbound
}

func (r *singleInboundRegistry) OptionTypes() []string {
	return []string{"test"}
}

func (r *singleInboundRegistry) CreateOptions(string) (any, bool) {
	return nil, true
}

func (r *singleInboundRegistry) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) (adapter.Inbound, error) {
	return r.inbound, nil
}

type startFailureInbound struct {
	closeCalls int
}

func (*startFailureInbound) Type() string {
	return "test"
}

func (*startFailureInbound) Tag() string {
	return "test"
}

func (*startFailureInbound) Start(adapter.StartStage) error {
	return errors.New("start failed")
}

func (i *startFailureInbound) Close() error {
	i.closeCalls++
	return nil
}
