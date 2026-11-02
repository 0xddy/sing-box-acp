package route

import (
	"context"

	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type networkLifecycleRouter struct {
	adapter.Router
	resets         atomic.Int64
	enter, release chan struct{}
}

func (r *networkLifecycleRouter) ResetNetwork() {
	r.resets.Add(1)
	if r.enter != nil {
		close(r.enter)
		<-r.release
	}
}

type networkLifecycleEndpoints struct {
	adapter.EndpointManager
	endpoints []adapter.Endpoint
}

func (m networkLifecycleEndpoints) Endpoints() []adapter.Endpoint { return m.endpoints }

type networkLifecycleInbounds struct{ adapter.InboundManager }

func (networkLifecycleInbounds) Inbounds() []adapter.Inbound { return nil }

type networkLifecycleOutbounds struct{ adapter.OutboundManager }

func (networkLifecycleOutbounds) Outbounds() []adapter.Outbound { return nil }

type networkLifecycleEndpoint struct {
	adapter.Endpoint
	context chan context.Context
}

func (e networkLifecycleEndpoint) InterfaceUpdated(ctx context.Context) { e.context <- ctx }

type networkLifecycleMonitor struct {
	tun.DefaultInterfaceMonitor
	closed chan struct{}
}

func (m networkLifecycleMonitor) DefaultInterface() *control.Interface {
	return &control.Interface{Index: 1, Name: "test-interface"}
}
func (m networkLifecycleMonitor) Close() error { close(m.closed); return nil }

func lifecycleNetworkManager(router *networkLifecycleRouter) *NetworkManager {
	ctx := pause.WithDefaultManager(context.Background())
	return &NetworkManager{
		ctx: ctx, logger: logger.NOP(), router: router,
		pauseManager: service.FromContext[pause.Manager](ctx),
		endpoint:     networkLifecycleEndpoints{}, inbound: networkLifecycleInbounds{}, outbound: networkLifecycleOutbounds{},
	}
}

func TestNetworkManagerPostStartSerializesInterfaceUpdates(t *testing.T) {
	router := &networkLifecycleRouter{}
	m := lifecycleNetworkManager(router)
	monitor := networkLifecycleMonitor{closed: make(chan struct{})}
	m.interfaceMonitor = monitor
	scope := adapter.NewScope(m.ctx, m.logger)
	defer scope.Close()
	// Coalesce notifications until the manager can safely reset its peers.
	for range 1000 {
		m.notifyInterfaceUpdate(monitor.DefaultInterface(), 0)
	}
	if router.resets.Load() != 0 {
		t.Fatal("interface update reset unstarted services")
	}
	if err := m.Start(adapter.StartStatePostStart, scope); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	before := router.resets.Load()
	m.notifyInterfaceUpdate(monitor.DefaultInterface(), 0)
	m.resetRunAccess.Lock()
	defer m.resetRunAccess.Unlock()
	if router.resets.Load() != before {
		t.Fatal("closed services were reset")
	}
}

func TestNetworkManagerCloseCancelsAndWaitsForInterfaceReset(t *testing.T) {
	router := &networkLifecycleRouter{enter: make(chan struct{}), release: make(chan struct{})}
	m := lifecycleNetworkManager(router)
	contexts := make(chan context.Context, 1)
	m.endpoint = networkLifecycleEndpoints{endpoints: []adapter.Endpoint{networkLifecycleEndpoint{context: contexts}}}
	monitorClosed := make(chan struct{})
	m.interfaceMonitor = networkLifecycleMonitor{closed: monitorClosed}
	scope := adapter.NewScope(m.ctx, m.logger)
	scope.Add(m.interfaceMonitor.Close)
	if err := m.Start(adapter.StartStatePostStart, scope); err != nil {
		t.Fatal(err)
	}
	m.notifyInterfaceUpdate(&control.Interface{Index: 1, Name: "test-interface"}, 0)
	var updateContext context.Context
	select {
	case updateContext = <-contexts:
	case <-time.After(time.Second):
		t.Fatal("interface callback did not start")
	}
	select {
	case <-router.enter:
	case <-time.After(time.Second):
		t.Fatal("interface reset did not start")
	}
	closeFinished := make(chan error, 1)
	go func() { closeFinished <- scope.Close() }()
	select {
	case <-updateContext.Done():
	case <-time.After(time.Second):
		t.Fatal("close did not cancel interface I/O")
	}
	select {
	case <-monitorClosed:
		t.Fatal("monitor torn down while reset still running")
	case <-closeFinished:
		t.Fatal("close returned while reset still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(router.release)
	select {
	case err := <-closeFinished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not finish after reset completed")
	}
	select {
	case <-monitorClosed:
	default:
		t.Fatal("monitor was not closed")
	}
	before := router.resets.Load()
	m.notifyInterfaceUpdate(&control.Interface{Index: 2, Name: "late-interface"}, 0)
	m.notifyInterfaceUpdate(nil, 0)
	m.resetRunAccess.Lock()
	defer m.resetRunAccess.Unlock()
	if router.resets.Load() != before {
		t.Fatal("closed manager admitted a reset or reactivated")
	}
}
