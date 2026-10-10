# Bazarish - facade-http

The HTTP facade for the [Bazarish](https://github.com/bazarish/docs-main)
messenger: the "last mile" between a client and the server infrastructure.

The messaging server is its only backend. It forwards exactly two requests there
and answers everything else with the same bare 404:

- `POST /t` - the sealed tunnel every client request travels inside. The real
  method, path and headers are encrypted, so the facade cannot tell a message
  from a mailbox poll, and the service node is reached through the same tunnel
  rather than by a path of its own.
- `GET /v1/server/card` - the signed server card, which is what lets a client
  seal that tunnel in the first place. Public by nature and identical for every
  caller, so serving it tells nobody anything.

The facade holds **no keys and no content at rest**; it parses nothing and
stores nothing identifying. Compromising it must not damage the server
infrastructure - it knows only the private-channel address of its backend and
the (end-to-end encrypted) traffic passing through. Clients reach it through
its own I2P destination, and through nothing else: it relays to the `listen`
socket on loopback, under a secret prefix known only to them.

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

`opsListen` opens a second, private socket carrying everything that is the
operator's: the signed `/healthz`, `GET`/`PUT /settings` and `POST /restart`. It is
never published to clients - on the public socket any of it would admit a facade
is here to a caller who does not know the secret base path. It speaks TLS and
answers only the key the admin panel presents, named in `opsClients`; the facade
makes its own certificate in `state` on first start and prints the hash of its
key, which is what the panel is configured with.

`directListen` opens a third socket serving exactly what the I2P destination
serves, over TLS with the same certificate. It is for a gateway the same
operator runs: given a route, that gateway dials this address instead of the
destination, and the flow does not enter I2P. Left out, the destination is the
only way in.

The backend is reached over TLS as well, pinned by the key the messaging server
prints: `"messaging": {"host": ..., "port": ..., "pin": ...}`.
