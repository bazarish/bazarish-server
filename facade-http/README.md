# Bazarish - facade-http

The HTTP facade for the [Bazarish](https://github.com/bazarish/docs-main)
messenger: the "last mile" between a client and the server infrastructure.

It has two backends and forwards exactly four requests to them; everything else
gets the same bare 404:

- `POST /t` and `GET /v1/server/card` go to the messaging server: the sealed
  tunnel of the mailbox calls and the signed card whose key seals it.
- `POST /n` and `GET /v1/node/card` go to the service node: the same for the
  account calls.

Inside a tunnel the method, path and headers are encrypted, so the facade cannot
tell a message from a mailbox poll; it learns only which backend a frame is for.
A card is public by nature and identical for every caller.

The facade holds **no key of the server or of a user, and no content at rest**;
its own keys are its address and its TLS certificate. It parses nothing and
stores nothing identifying. Compromising it must not damage the server
infrastructure - it knows only the private-channel addresses of its backends and
the (end-to-end encrypted) traffic passing through. Clients reach it through its
own I2P destination, which relays to the `listen` socket on loopback.

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

The facade's address is its I2P destination, published blinded (b33): the network
database does not give it away, so clients learn it only from the server
descriptor. It answers at `/`. The key is minted at the first start and kept in
`state` (`facade-dest-0.key`), and the facade prints the address.
`POST /new-address` on the ops socket mints a new key, answers with the new
address and the old one, and restarts the facade to publish it; a client that
knows only the old address loses the server until it is given the new one. The
reseed archive is not here - it is served by the portal, which is what faces the
clearnet. Anything else - an unknown path, `/healthz` - is the same bare 404.

`opsListen` opens a second, private socket carrying everything that is the
operator's: the signed `/healthz`, `GET`/`PUT /settings` (which also reports the
facade's address), `POST /new-address` and `POST /restart`. It is
never published to clients - on the public socket anyone holding the address
could reach it. It speaks TLS and
answers only the key the admin panel presents, named in `opsClients`; the facade
makes its own certificate in `state` on first start and prints the hash of its
key, which is what the panel is configured with.

`directListen` opens a third socket serving exactly what the I2P destination
serves, over TLS with the same certificate. It is for a gateway the same
operator runs: given a route, that gateway dials this address instead of the
destination, and the flow does not enter I2P. Left out, the destination is the
only way in.

Both backends are reached over TLS, each pinned by the key it prints:
`"messaging"` and `"serviceNode"`, each `{"host": ..., "port": ..., "pin": ...}`.
