# Juicity inbound

Juicity accepts TCP, UDP over streams, and Underlay UDP on one UDP listening port. Build with `with_quic`.

```json
{
  "type": "juicity",
  "tag": "juicity-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "alice",
      "uuid": "059032a9-7d40-4a96-9bb1-36823d848068",
      "password": "replace-with-a-secret"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/sing-box/fullchain.pem",
    "key_path": "/etc/sing-box/key.pem"
  }
}
```

Each UUID must be unique within an inbound. A password is required. `name` identifies the user to routing and accounting. Removing or changing a credential closes its sessions and Underlay mappings on a live update.

TLS uses version 1.3 and ALPN `h3`. `congestion_control` accepts `bbr` (default), `cubic`, or `new_reno`. `auth_timeout` defaults to `10s`. Set `max_concurrent_streams` to at least 30 if specified.
