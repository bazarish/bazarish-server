# Bazarish - facade-http

The HTTP facade for the [Bazarish](https://github.com/bazarish/docs-main)
messenger: the "last mile" between a client and the server infrastructure.

It forwards exactly two requests to the messaging server and answers everything
else with the same bare 404:

- `POST /t` - the sealed tunnel every client request travels inside. The real
  method, path and headers are encrypted, so the facade cannot tell a message
  from a mailbox poll, and the service node is reached through the same tunnel
  rather than by a path of its own.
- `GET /v1/server/card` - the signed server card, which is what lets a client
  seal that tunnel in the first place. Public by nature and identical for every
  caller, so serving it tells nobody anything.

The facade holds **no keys and no content at rest**; it parses nothing and
stores nothing identifying. Compromising it must not damage the server
infrastructure - it knows only the private-channel addresses of its backends
and the (end-to-end encrypted) traffic passing through. It is meant to sit
behind a reverse proxy (Caddy, nginx, ...) published at a secret URI known only
to clients.

## Build

Requires CMake >= 3.20, C++20, OpenSSL >= 3.5. `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/bazarish-server
cmake -S bazarish-server -B build && cmake --build build -j4
ctest --test-dir build
```

## Run

```
bazarish-facade-http --config <path>
```

Everything is in that file (see `config.example.json`); nothing is settable on
the command line.

`basePath` is mandatory and stripped before forwarding: what the facade serves
is reachable only under that secret prefix, and clients learn it only from the
facade URL in the server descriptor. The reseed archive is not here - it is
served by the portal, which is what faces the clearnet. Anything else - an
unknown path, the API root, `/healthz` - is the same bare 404, so a scan of the
host learns nothing. The signed canonical request
path is the post-strip path, so signatures verify on the backend regardless.

Set `"public": true` instead only when a fronting reverse proxy already publishes this
facade under a secret URI of its own; the facade refuses to start with neither.

`opsListen` opens a second, private socket that serves only the
operator-signed `/healthz` for the admin panel. It is never published to clients.
