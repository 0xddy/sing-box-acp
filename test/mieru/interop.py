"""Linux loopback interoperability with unmodified mieru/mita v3.39.0."""
import argparse
import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def exact(conn, length):
    result = bytearray()
    while len(result) < length:
        chunk = conn.recv(length - len(result))
        if not chunk:
            raise EOFError("short TCP response")
        result += chunk
    return bytes(result)


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        raw = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        domain = host.encode("ascii")
        raw = bytes([3, len(domain)]) + domain
    return raw + struct.pack("!H", port)


def unpack_address(read):
    kind = read(1)
    if kind == b"\x03":
        host = read(read(1)[0]).decode("ascii")
    else:
        host = str(ipaddress.ip_address(read({b"\x01": 4, b"\x04": 16}[kind])))
    return host, struct.unpack("!H", read(2))[0]


def socks(port, command, host, dest_port):
    s = socket.create_connection(("127.0.0.1", port), timeout=6)
    try:
        s.sendall(b"\x05\x01\x00")
        assert exact(s, 2) == b"\x05\x00"
        s.sendall(bytes([5, command, 0]) + address(host, dest_port))
        status = exact(s, 3)
        if status != b"\x05\x00\x00":
            raise ConnectionRefusedError(f"SOCKS response {status.hex()}")
        return s, unpack_address(lambda n: exact(s, n))
    except BaseException:
        s.close()
        raise


class Greeting(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-mieru-test\r\n")
        while chunk := self.request.recv(65536):
            self.request.sendall(chunk)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        sock.sendto(payload, self.client_address)


@contextlib.contextmanager
def target(base, handler, host, port=0):
    class Server(base):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        daemon_threads = True
    with Server((host, port), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


@contextlib.contextmanager
def process(args, env):
    with tempfile.TemporaryFile(mode="w+b") as output:
        child = subprocess.Popen(args, env=dict(os.environ, **env), stdout=output, stderr=output)
        try:
            yield child
        except BaseException:
            output.seek(0)
            print(output.read().decode(errors="replace")[-6000:])
            raise
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def ready(port, processes):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("proxy exited at startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise TimeoutError("SOCKS port did not start")


def wait_for_bind(port, transport, processes):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("server exited at startup")
        for family in ["", "6"]:
            for line in Path(f"/proc/net/{transport}{family}").read_text().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].split(":")[-1], 16) == port and (transport == "udp" or fields[3] == "0A"):
                    return
        time.sleep(.05)
    raise TimeoutError(f"{transport} port {port} did not bind")


def traffic(proxy, tcp4, tcp6, udp4, udp6):
    for host, port in [("127.0.0.1", tcp4), ("::1", tcp6), ("localhost", tcp4)]:
        conn, _ = socks(proxy, 1, host, port)
        with conn:
            assert exact(conn, len(b"SSH-2.0-mieru-test\r\n")) == b"SSH-2.0-mieru-test\r\n"
            payload = bytes(range(256)) * 145
            conn.sendall(payload)
            assert exact(conn, len(payload)) == payload
    control, relay = socks(proxy, 3, "0.0.0.0", 0)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(6)
        for i, (host, port) in enumerate([("127.0.0.1", udp4), ("::1", udp6), ("localhost", udp4)] * 2):
            payload = bytes([0, i, 255]) * 57
            udp.sendto(bytes(3) + address(host, port) + payload, ("127.0.0.1", relay[1]))
            try:
                packet = udp.recv(65535)
            except TimeoutError as exc:
                raise AssertionError(f"no UDP reply from {host}:{port} (datagram {i})") from exc
            reader = io.BytesIO(packet)
            assert reader.read(3) == bytes(3)
            _, source_port = unpack_address(reader.read)
            assert source_port == port and reader.read() == payload


def exercise(args, directory, direction, transport, targets, wrong_password=False):
    ports = []
    while len(ports) < 3:
        port = free_port()
        if port not in ports:
            ports.append(port)
    server_port, proxy, rpc = ports
    user = dict(name="alice", password="test-password")
    credential = dict(user, password="obsolete") if wrong_password else user
    binding = dict(port=server_port, protocol=transport.upper())
    server = dict(trafficPattern={"seed": 7}, listenIPAddress="127.0.0.1", portBindings=[binding], users=[dict(user, allowLoopbackIP=True)])
    outbound = dict(type="mieru", tag="m", server="mieru.test", domain_resolver="endpoint", traffic_pattern="CAc=", server_ports=[f"{server_port}:{server_port}"], transport=transport, username="alice", password=credential["password"], mtu=1400, multiplexing="high", handshake_mode="no_wait")
    if direction == "inbound":
        box = dict(inbounds=[dict(type="mieru", tag="m", listen="127.0.0.1", listen_port=server_port, users=[user], traffic_pattern="CAc=", transport=transport, mtu=1400, user_hint_is_mandatory=True)], outbounds=[dict(type="direct", tag="direct")])
        box["route"] = {"rules": [{"auth_user": ["alice"], "action": "route", "outbound": "direct"}, {"action": "reject"}]}
        profile = dict(profileName="local", trafficPattern={"seed": 7}, user=credential, servers=[dict(ipAddress="127.0.0.1", portBindings=[binding])], handshakeMode="HANDSHAKE_STANDARD")
        official = dict(profiles=[profile], activeProfile="local", rpcPort=rpc, socks5Port=proxy)
        binary, config_var = args.mieru, "MIERU_CONFIG_JSON_FILE"
    else:
        box = dict(inbounds=[dict(type="socks", tag="local", listen="127.0.0.1", listen_port=proxy)], outbounds=[outbound])
        box["dns"] = {"servers": [{"type": "hosts", "tag": "endpoint", "predefined": {"mieru.test": "127.0.0.1"}}]}
        official, binary, config_var = server, args.mita, "MITA_CONFIG_JSON_FILE"
    cfg, ref = directory / "box.json", directory / "reference.json"
    cfg.write_text(json.dumps(box))
    ref.write_text(json.dumps(official))
    env = {config_var: str(ref), "MITA_UDS_PATH": str(directory / "rpc.sock"), "MITA_INSECURE_UDS": "1", "HOME": str(directory)}
    subprocess.run([args.box, "check", "-c", str(cfg)], check=True)
    with process([binary, "run"], env) as official_proc, process([args.box, "run", "-c", str(cfg)], {}) as box_proc:
        wait_for_bind(server_port, transport, [box_proc, official_proc])
        ready(proxy, [box_proc, official_proc])
        if wrong_password:
            try:
                conn, _ = socks(proxy, 1, "127.0.0.1", targets[0])
                with conn:
                    data = conn.recv(20)
            except (OSError, EOFError):
                data = b""
            assert not data, "invalid credential reached target"
        else:
            traffic(proxy, *targets)
            if direction == "inbound":
                # Keep the port reserved without listening. The inbound must
                # propagate the failure before reporting SOCKS success.
                with socket.socket() as closed_target:
                    closed_target.bind(("127.0.0.1", 0))
                    try:
                        conn, _ = socks(proxy, 1, *closed_target.getsockname())
                    except (ConnectionRefusedError, EOFError):
                        pass
                    else:
                        conn.close()
                        raise AssertionError("inbound reported success for refused target")
    print(direction, transport, "bad credentials" if wrong_password else "TCP + UDP", "PASS", flush=True)


def main():
    parser = argparse.ArgumentParser()
    for name in ["box", "mieru", "mita"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    for binary in [args.mieru, args.mita]:
        assert subprocess.check_output([binary, "version"], text=True).strip() == "3.39.0"
    with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
        targets = [stack.enter_context(target(base, handler, host)) for base, handler in [(socketserver.ThreadingTCPServer, Greeting), (socketserver.ThreadingUDPServer, Echo)] for host in ["127.0.0.1", "::1"]]
        # localhost can resolve to either family on both reference implementations.
        stack.enter_context(target(socketserver.ThreadingTCPServer, Greeting, "::1", targets[0]))
        stack.enter_context(target(socketserver.ThreadingUDPServer, Echo, "::1", targets[2]))
        for direction in ["inbound", "outbound"]:
            for transport in ["tcp", "udp"]:
                exercise(args, Path(temp), direction, transport, targets)
                exercise(args, Path(temp), direction, transport, targets, wrong_password=True)


if __name__ == "__main__":
    main()
