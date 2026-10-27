---
icon: material/new-box
---

!!! question "Since sing-box 1.12.0"

### Structure

```json
{
  "type": "anytls",
  "tag": "anytls-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "padding_scheme": [],
  "tls": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

AnyTLS users.

#### padding_scheme

AnyTLS padding scheme line array.

Default padding scheme:

```json
[
  "stop=8",
  "0=30-30",
  "1=100-400",
  "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
  "3=9-9,500-1000",
  "4=500-1000",
  "5=500-1000",
  "6=500-1000",
  "7=500-1000"
]
```

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### web (ACP extension)

With TLS enabled, ordinary website requests can use a fixed response or a fixed
upstream reverse proxy:

```json
{"type": "static", "content": "<h1>Welcome</h1>"}
```

```json
{"type": "proxy", "url": "https://www.example.com"}
```

Static mode serves the configured content at every path. Website requests share
the TLS listener and do not enter AnyTLS user traffic accounting. Port 80 is not
opened.

The HTTP response profile follows Apache 2.4 with `ServerTokens Prod`,
`ServerSignature Off` and `TraceEnable Off`. Responses advertise one
`Server: Apache` header. Static ETags use hexadecimal size and microsecond mtime,
with a `-gzip` suffix for compressed representations. Like mod_deflate, known
bodies no larger than 68 bytes are not compressed. GET/HEAD/POST, conditional requests,
ranges and OPTIONS (including `OPTIONS *`) are supported. Unknown static methods
return 501; recognized but unsupported methods return 405. Locally generated
errors use Apache-style HTML. Backend connection failures return 503, response
timeouts 504, and other gateway failures 502. TRACE and CONNECT are not forwarded.

Reverse proxying preserves application response bodies, statuses, cookies and
cache validators, replaces the backend Server header and removes unsupported
Alt-Svc advertisements. Interim responses, streaming and protocol upgrades retain
the same server identity.

HTTP/1 serialization follows Apache-style header order, ETag capitalization and
status lines. Common parser errors generated before Handler entry are rendered
as HTML without Go's plain-text reason suffixes. Request lines and individual
fields are limited to 8190 bytes, with at most 100 fields. HTTP/1 has a five-second
idle timeout and 100-request connection limit; explicit keep-alive requests
receive the corresponding Keep-Alive header.

The HTTP/2 engine actually uses 100 concurrent streams, 16384-byte frames,
65535-byte stream windows and 4096-byte header tables. The initial serializer
omits only protocol-default values and the advisory header-list limit. The
connection window increment is 2147418112. These initial frames are compared
against Apache 2.4.69 in Docker.

Complete, parseable textual HTTP/2.0 and HTTP/3.0 request lines on HTTP/1
connections are adapted to HTTP/1.1, matching Apache's version-probe behavior.
Only the version token changes; Go's request parser determines body framing,
and bodies/trailers pass through unchanged. Real HTTP/2 uses ALPN and bypasses
this adapter; its preface is not rewritten. This does not provide QUIC/HTTP/3.
417 reflects the HTML-escaped Expect value, including repeated fields. Locally
generated 416 omits Content-Range and Content-Length: closing HTTP/1 uses EOF,
persistent HTTP/1 uses chunking, HTTP/2 uses END_STREAM. HEAD errors have no body;
416 and HEAD 417 omit the length header. Upstream application 416 responses keep
their own body and range metadata.

This is not an Apache httpd implementation. TLS, subsequent HTTP/2 scheduling and
HPACK, compressed bytes and request parsing still use Go. Version adaptation is
limited to the two structurally valid probes above; other malformed versions,
parser failures and invalid body framing remain subject to Go's rejection.
HTTP/2 uses ALPN without advertising
Upgrade: h2. SNI/Host virtual-host policy, timeout boundaries and all combinations
of malformed requests are not replicated. Catch-all content, certificates and
upstream application content or headers may also be distinguishable.

See `common/webserver/testdata/apache/README.md` for the reproducible local
comparison and its explicit normalization contract and known differences.

References: [Apache core](https://httpd.apache.org/docs/2.4/mod/core.html) and
[mod_deflate](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html).
