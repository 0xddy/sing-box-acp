package route

import (
	"context"
	"sync"
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

func (m networkLifecycleMonitor) DefaultInterface() *control.Interface { return nil }
func (m networkLifecycleMonitor) Close() error                         { close(m.closed); return nil }

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
	iif := &control.Interface{Index: 1, Name: "test-interface"}
	m.updateInterface(context.Background(), iif)
	if router.resets.Load() != 0 {
		t.Fatal("interface update reset unstarted services")
	}
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-ready
		for range 1000 {
			m.updateInterface(context.Background(), iif)
		}
	}()
	go func() {
		defer wg.Done()
		<-ready
		if err := m.Start(adapter.StartStatePostStart); err != nil {
			t.Error(err)
		}
	}()
	close(ready)
	wg.Wait()
	before := router.resets.Load()
	m.updateInterface(context.Background(), iif)
	if router.resets.Load() != before+1 {
		t.Fatal("post-start interface update did not reset services")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m.updateInterface(context.Background(), iif)
	if router.resets.Load() != before+1 {
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
	if err := m.Start(adapter.StartStatePostStart); err != nil {
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
	go func() { closeFinished <- m.Close() }()
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
	if err := m.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	m.updateInterface(context.Background(), &control.Interface{Index: 2, Name: "late-interface"})
	if router.resets.Load() != before {
		t.Fatal("closed manager admitted a reset or reactivated")
	}
}
