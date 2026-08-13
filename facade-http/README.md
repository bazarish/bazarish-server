# Bazarish - facade-http

The HTTP facade for the [Bazarish](https://github.com/bazarish/docs-main)
messenger: the "last mile" between a client and the server infrastructure.

A transparent reverse proxy that routes client requests by path prefix:

- `/v1/messaging/*` -> the [messaging server](https://github.com/bazarish/server-core)
- `/v1/account/*` -> the [service node](https://github.com/bazarish/service-node)

The facade holds **no keys and no content at rest**; it parses nothing and
stores nothing identifying. Compromising it must not damage the server
infrastructure - it knows only the private-channel addresses of its backends
and the (end-to-end encrypted) traffic passing through. It is meant to sit
behind a reverse proxy (Caddy, nginx, ...) published at a secret URI known only
to clients.

## Build

Requires CMake >= 3.20, C++20, OpenSSL >= 3.0. `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/facade-http
cmake -S . -B build && cmake --build build -j
ctest --test-dir build
```

## Run

```
bazarish-facade-http --base-path <secret-uri-prefix> | --public
                     [--listen <host> <port>]
                     [--ops-listen <host> <port>]
                     [--messaging <host> <port>]
                     [--account <host> <port>]
```

`--base-path` is mandatory and stripped before forwarding: the whole clearnet
API, the unauthenticated first reseed included, is reachable only under that
secret prefix, and clients learn it only from the facade URL in the server
descriptor. Anything else - an unknown path, the API root, `/healthz` - is the
same bare 404, so a scan of the host learns nothing. The signed canonical request
path is the post-strip path, so signatures verify on the backend regardless.

Pass `--public` instead only when a fronting reverse proxy already publishes this
facade under a secret URI of its own; the facade refuses to start with neither.

`--ops-listen` opens a second, private socket that serves only the
operator-signed `/healthz` for the admin panel. It is never published to clients.
