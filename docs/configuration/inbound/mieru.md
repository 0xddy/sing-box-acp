# Mieru

## Configuration

```json
{
  "type": "mieru",
  "tag": "mieru-in",
  "listen": "::",
  "listen_port": 2027,
  "users": [
    {
      "name": "alice",
      "password": "example-password"
    }
  ],
  "transport": "tcp"
}
```

Mieru authenticates with a username and password. Keep both clocks synchronized. `transport` selects the connection between the client and server, either `tcp` (default) or `udp`. Both carry TCP and UDP traffic without TLS or QUIC.
Use the common listen options. Each user needs a unique `name`. Usernames and passwords must each be 1–64 bytes. An empty list binds the port and denies authentication. Removing a user or rotating a password closes that user's existing sessions. Routes can match the authenticated name with `auth_user`.

`user_hint_is_mandatory` defaults to false. Enable it to require the protocol's username hint from clients.

`mtu` defaults to 1400 and accepts values from 1280 through 1500. Set `traffic_pattern` to an official Base64 traffic pattern, or omit it for upstream defaults. [Traffic patterns](https://github.com/enfein/mieru/blob/v3.39.0/docs/traffic-pattern.md)

A TCP client waiting for the CONNECT response receives the result of dialing the destination. When a `no_wait` client includes payload with its request, routing rules can sniff those bytes before dialing.
