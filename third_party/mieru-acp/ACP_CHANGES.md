# ACP integration

Upstream is [enfein/mieru v3.39.0](https://github.com/enfein/mieru/tree/bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06). The module path and upstream license are preserved.

- The managed server accepts an empty initial user table and exposes authenticated sessions to the embedding router. The standalone server still requires users at startup.
- A credential lease links initial authentication, session attachment, TCP socket reuse and UDP session lookup. Replacing credentials retires only changed users. Kicking a user rotates its lease while retaining the credential.
- The early client connection sends a pending request on first read or first write. The wire format is unchanged.
- Linux interoperability tests build clean upstream binaries from the pinned commit and exercise both directions. The embedded source is never used to build those reference binaries.
