# bazarish-gateway

A private HTTPS transport gateway for Bazarish clients: it runs the I2P router
so the client does not have to, which is what a phone or a laptop on battery
wants. The client switches its own router off and speaks to this over one
pinned-TLS WebSocket per flow; nothing above the transport seam changes.

It is bound to no Bazarish server and keeps nothing once a session has expired.
The operator sees every destination its clients dial and holds the keys of every
destination it mints for them, so it is for people who already trust whoever
runs it. `PROTOCOL.md` is the authority for the wire and for what that trust
covers.

## Building

```
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j4
ctest --test-dir build
```

CMake >= 3.20, C++20, OpenSSL >= 3.0.

## Deploying

The daemon speaks HTTP on a socket of its own; TLS, the public address and the
cover site belong to the front it listens behind, and that front can be
anything - a real site, a holding page, a `proxy_pass` to somebody else's.

Checking the token at the front as well is worth doing: it keeps unauthorised
requests off the daemon entirely. It is a recommendation, not a mechanism - the
gateway answers for its own admission either way.

`bazarish-gateway --help` lists the rest; `config.example.json` is a starting
point.
