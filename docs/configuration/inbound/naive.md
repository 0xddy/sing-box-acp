!!! quote "Changes in sing-box 1.13.0"

    :material-plus: [quic_congestion_control](#quic_congestion_control)

### Structure

```json
{
"type": "naive",
"tag": "naive-in",
"network": "udp",
...
// Listen Fields

"users": [
{
"username": "sekai",
"password": "password"
}
],
"quic_congestion_control": "",
"tls": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

#### users

Naive users. An empty list keeps the website available while denying proxy authentication.
Usernames must be unique; neither username nor password may be empty.

#### quic_congestion_control

!!! question "Since sing-box 1.13.0"

QUIC congestion control algorithm.

| Algorithm      | Description                     |
|----------------|---------------------------------|
| `bbr`          | BBR                             |
| `cubic`        | CUBIC                           |
| `reno`         | New Reno                        |

`bbr` is used by default.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

TLS is required with QUIC or the ACP `web` option. Certificate updates retain listeners.

#### web (ACP)

Optional website configuration shared with AnyTLS: `{"type":"static","content":"<h1>Website</h1>"}`
or `{"type":"proxy","url":"https://website.example.com"}`. Normal requests and rejected
CONNECT requests follow website rules without proxy authentication challenges.
Only authenticated CONNECT streams enter routing and accounting.

The website's 30-second request deadline is cleared for authenticated tunnels.
Each pending write has a two-minute no-progress deadline, cleared after writing;
revocation and shutdown interrupt blocked operations. There is no tunnel idle-read
deadline. Client, destination and intermediate-network timeouts remain independent.

Limits are 256 TCP/QUIC connections per inbound, 100 concurrent streams per connection
and 4096 authenticated streams per inbound. These bounds are not benchmark results.
QUIC 0-RTT is disabled. HTTP/2 uses the engine's current scheduler and advertises
its actual settings; Apache priority settings, TLS/QUIC bytes and timing may differ.
