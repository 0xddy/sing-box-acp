V2Ray Transport is a set of private protocols invented by v2ray, and has contaminated the names of other protocols, such
as `trojan-grpc` in clash.

### Structure

```json
{
  "type": ""
}
```

Available transports:

* HTTP
* WebSocket
* QUIC
* gRPC
* HTTPUpgrade
* XHTTP (ACP)

!!! warning "Difference from v2ray-core"

    * No TCP transport, plain HTTP is merged into the HTTP transport.
    * No mKCP transport.
    * No DomainSocket transport.

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### XHTTP (ACP)

```json
{
  "type": "xhttp",
  "mode": "auto",
  "host": "proxy.example.com",
  "path": "/proxy/",
  "headers": { "X-Site": "edge" },
  "x_padding_bytes": "100-1000"
}
```

This ACP transport supports HTTP/2 with TLS or REALITY. When using VLESS, leave the user and outbound `flow` empty. Omit the entire `transport` object to use raw TCP with Vision.

| Mode | Requests for one connection |
| --- | --- |
| `packet-up` | Numbered upload requests and one streaming download GET. The receiver reorders packets within a bounded window. |
| `stream-up` | One streaming upload request and a separate download GET. |
| `stream-one` | One bidirectional streaming POST by default. |
| `auto` (default) | Servers accept all three modes. Clients use `packet-up` with ordinary TLS. REALITY uses `stream-one`, or `stream-up` with separate download settings. |

| Settings | Behavior |
| --- | --- |
| `host`, `path`, `headers` | `host` selects the HTTP authority independently of TLS SNI. Paths default to `/` and accept a query string. Headers are applied to client requests or server responses. |
| `x_padding_bytes`, `x_padding_obfs_mode`, `x_padding_placement`, `x_padding_key`, `x_padding_header`, `x_padding_method` | Default padding is 100–1000 bytes in the Referer query. Obfuscation supports `header`, `cookie`, `query`, `queryInHeader`, and the `repeat-x` and `tokenish` methods. Configure matching settings on both ends. |
| `session_placement`, `session_key`, `seq_placement`, `seq_key` | Place the session ID and packet sequence in the path (default), query, header or cookie. `session_table` and `session_length` together select a custom client ID alphabet and length. |
| `uplink_http_method`, `uplink_data_placement`, `uplink_data_key`, `uplink_chunk_size` | Uploads default to POST. Packet uploads can use the body, numbered headers or cookies. GET uploads require header or cookie data and explicit `packet-up`. |
| `sc_max_each_post_bytes`, `sc_min_posts_interval_ms`, `sc_max_buffered_posts` | Packet size (default 1,000,000 bytes), pacing (30 ms), and reorder window (30 packets). |
| `sc_stream_up_server_secs`, `no_grpc_header`, `no_sse_header`, `server_max_header_bytes` | Streaming upload heartbeat (20–80 seconds), optional content-type headers, and incoming header size limit (16 KiB). |
| `xmux` (client) | Supports `max_connections` or `max_concurrency`, `c_max_reuse_times`, `h_max_request_times`, `h_max_reusable_secs` and `h_keep_alive_period` (seconds). These manage HTTP connections independently of VLESS multiplexing. |
| `download_settings` (client) | Overrides the split download `host` and/or `path`. The configured server address, dialer and TLS settings are shared. |

Range settings accept a single number, a string such as `"100-1000"`, or a two-element array. A `stream-one` response stays open until the upload completes after a download half-close, so the upload tail can still be delivered. Split modes can return download EOF independently. Packet uploads have no separate wire-level upload FIN.

### HTTP

```json
{
  "type": "http",
  "host": [],
  "path": "",
  "method": "",
  "headers": {},
  "idle_timeout": "15s",
  "ping_timeout": "15s"
}
```

!!! warning "Difference from v2ray-core"

    TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.

#### host

List of host domain.

The client will choose randomly and the server will verify if not empty.

#### path

!!! warning

    V2Ray's documentation says that the path between the server and the client must be consistent, 
    but the actual code allows the client to add any suffix to the path.
    sing-box uses the same behavior as V2Ray, but note that the behavior does not exist in `WebSocket` and `HTTPUpgrade` transport.

Path of HTTP request.

The server will verify.

#### method

Method of HTTP request.

The server will verify if not empty.

#### headers

Extra headers of HTTP request.

The server will write in response if not empty.

#### idle_timeout

In HTTP2 server:

Specifies the time until idle clients should be closed with a GOAWAY frame. PING frames are not considered as activity.

In HTTP2 client:

Specifies the period of time after which a health check will be performed using a ping frame if no frames have been
received on the connection.Please note that a ping response is considered a received frame, so if there is no other
traffic on the connection, the health check will be executed every interval. If the value is zero, no health check will
be performed.

Zero is used by default.

#### ping_timeout

In HTTP2 client:

Specifies the timeout duration after sending a PING frame, within which a response must be received.
If a response to the PING frame is not received within the specified timeout duration, the connection will be closed.
The default timeout duration is 15 seconds.

### WebSocket

```json
{
  "type": "ws",
  "path": "",
  "headers": {},
  "max_early_data": 0,
  "early_data_header_name": ""
}
```

#### path

Path of HTTP request.

The server will verify.

#### headers

Extra headers of HTTP request.

The server will write in response if not empty.

#### max_early_data

Allowed payload size is in the request. Enabled if not zero.

#### early_data_header_name

Early data is sent in path instead of header by default.

To be compatible with Xray-core, set this to `Sec-WebSocket-Protocol`.

It needs to be consistent with the server.

### QUIC

```json
{
  "type": "quic"
}
```

!!! warning "Difference from v2ray-core"

    No additional encryption support:
    It's basically duplicate encryption. And Xray-core is not compatible with v2ray-core in here.

### gRPC

!!! note ""

    standard gRPC has good compatibility but poor performance and is not included by default, see [Installation](/installation/build-from-source/#build-tags).

```json
{
  "type": "grpc",
  "service_name": "TunService",
  "idle_timeout": "15s",
  "ping_timeout": "15s",
  "permit_without_stream": false
}
```

#### service_name

Service name of gRPC.

#### idle_timeout

In standard gRPC server/client:

If the transport doesn't see any activity after a duration of this time,
it pings the client to check if the connection is still active.

In default gRPC server/client:

It has the same behavior as the corresponding setting in HTTP transport.

#### ping_timeout

In standard gRPC server/client:

The timeout that after performing a keepalive check, the client will wait for activity.
If no activity is detected, the connection will be closed.

In default gRPC server/client:

It has the same behavior as the corresponding setting in HTTP transport.

#### permit_without_stream

In standard gRPC client:

If enabled, the client transport sends keepalive pings even with no active connections.
If disabled, when there are no active connections, `idle_timeout` and `ping_timeout` will be ignored and no keepalive
pings will be sent.

Disabled by default.

### HTTPUpgrade

```json
{
  "type": "httpupgrade",
  "host": "",
  "path": "",
  "headers": {}
}
```

#### host

Host domain.

The server will verify if not empty.

#### path

Path of HTTP request.

The server will verify.

#### headers

Extra headers of HTTP request.

The server will write in response if not empty.
