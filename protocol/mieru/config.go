package mieru

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/enfein/mieru/v3/apis/trafficpattern"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/option"
	"google.golang.org/protobuf/proto"
)

func settings(o option.MieruOptions) (pb.TransportProtocol, *pb.TrafficPattern, error) {
	transport := pb.TransportProtocol_TCP
	switch o.Transport {
	case "", "tcp":
	case "udp":
		transport = pb.TransportProtocol_UDP
	default:
		return 0, nil, fmt.Errorf("invalid mieru transport %q", o.Transport)
	}
	if o.MTU != 0 && (o.MTU < 1280 || o.MTU > 1500) {
		return 0, nil, fmt.Errorf("mtu must be between 1280 and 1500")
	}
	if o.TrafficPattern == "" {
		return transport, nil, nil
	}
	pattern, err := trafficpattern.Decode(o.TrafficPattern)
	if err == nil {
		err = trafficpattern.Validate(pattern)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("invalid traffic_pattern: %w", err)
	}
	return transport, pattern, nil
}

func credentials(users []option.MieruUser) []*pb.User {
	result := make([]*pb.User, 0, len(users))
	for _, u := range users {
		result = append(result, &pb.User{Name: proto.String(u.Name), Password: proto.String(u.Password)})
	}
	return result
}

func clientProfile(o option.MieruOutboundOptions) (*pb.ClientProfile, error) {
	transport, pattern, err := settings(o.MieruOptions)
	if err != nil {
		return nil, err
	}
	if (len(o.ServerPorts) == 0) == (o.ServerPort == 0) {
		return nil, fmt.Errorf("set exactly one of server_port and server_ports")
	}
	endpoint := &pb.ServerEndpoint{}
	if net.ParseIP(o.Server) != nil {
		endpoint.IpAddress = proto.String(o.Server)
	} else {
		endpoint.DomainName = proto.String(o.Server)
	}
	if o.ServerPort != 0 {
		endpoint.PortBindings = []*pb.PortBinding{{Port: proto.Int32(int32(o.ServerPort)), Protocol: transport.Enum()}}
	}
	for _, value := range o.ServerPorts {
		first, last, ranged := strings.Cut(value, ":")
		a, e := strconv.ParseUint(first, 10, 16)
		if e != nil || a == 0 {
			return nil, fmt.Errorf("invalid server_ports entry %q", value)
		}
		binding := &pb.PortBinding{Port: proto.Int32(int32(a)), Protocol: transport.Enum()}
		if ranged {
			b, e := strconv.ParseUint(last, 10, 16)
			if e != nil || b < a {
				return nil, fmt.Errorf("invalid server_ports range %q", value)
			}
			binding.Port = nil
			binding.PortRange = proto.String(fmt.Sprintf("%d-%d", a, b))
		}
		endpoint.PortBindings = append(endpoint.PortBindings, binding)
	}
	level := pb.MultiplexingLevel_MULTIPLEXING_LOW
	switch o.Multiplexing {
	case "", "low":
	case "off":
		level = pb.MultiplexingLevel_MULTIPLEXING_OFF
	case "middle":
		level = pb.MultiplexingLevel_MULTIPLEXING_MIDDLE
	case "high":
		level = pb.MultiplexingLevel_MULTIPLEXING_HIGH
	default:
		return nil, fmt.Errorf("invalid multiplexing %q", o.Multiplexing)
	}
	mode := pb.HandshakeMode_HANDSHAKE_STANDARD
	switch o.HandshakeMode {
	case "", "standard":
	case "no_wait":
		mode = pb.HandshakeMode_HANDSHAKE_NO_WAIT
	default:
		return nil, fmt.Errorf("invalid handshake_mode %q", o.HandshakeMode)
	}
	return &pb.ClientProfile{
		ProfileName: proto.String("sing-box"), Servers: []*pb.ServerEndpoint{endpoint},
		User: &pb.User{Name: proto.String(o.Username), Password: proto.String(o.Password)},
		Mtu:  proto.Int32(int32(o.MTU)), TrafficPattern: pattern,
		Multiplexing: &pb.MultiplexingConfig{Level: level.Enum()}, HandshakeMode: mode.Enum(),
	}, nil
}
