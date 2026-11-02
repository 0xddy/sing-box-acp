package inbound

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	scope        *adapter.Scope
	registry     adapter.InboundRegistry
	endpoint     adapter.EndpointManager
	access       sync.Mutex
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
	inbounds := slices.Clone(m.inbounds)
	m.access.Unlock()
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		err := scope.Start(name, inbound, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.inbounds)
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	defer m.access.Unlock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		return os.ErrInvalid
	}
	delete(m.inboundByTag, tag)
	m.inbounds = slices.DeleteFunc(m.inbounds, func(it adapter.Inbound) bool { return it == inbound })
	if m.scope != nil {
		return m.scope.CloseChild(inbound)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	inbound, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	old, loaded := m.inboundByTag[tag]
	if m.scope == nil && loaded {
		return E.New("duplicate inbound tag: ", tag)
	}
	if m.scope != nil {
		name := "inbound/" + inbound.Type() + "[" + tag + "]"
		for _, stage := range adapter.ListStartStages {
			if err := m.scope.Start(name, inbound, stage); err != nil {
				return errors.Join(err, m.scope.CloseChild(inbound))
			}
		}
		if loaded {
			if err := m.scope.CloseChild(old); err != nil {
				return errors.Join(err, m.scope.CloseChild(inbound))
			}
			m.inbounds = slices.DeleteFunc(m.inbounds, func(it adapter.Inbound) bool { return it == old })
		}
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	return nil
}
