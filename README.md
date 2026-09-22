# bazarish-gateway

A private HTTPS transport gateway for Bazarish clients.

A client normally runs its own I2P router. On a phone that costs battery, a
netDb and a set of tunnels the device would rather not pay for. This daemon runs
the router instead: the client switches its own off, speaks to this over one
pinned-TLS WebSocket per flow, and everything above the transport seam stays
exactly as it was.

It is a **client-side abstraction**. It is bound to no Bazarish server, carries
no account, and keeps nothing once a session has expired. The case it exists for
is a self-hoster running one for himself and the people who already trust him:
the operator sees every destination a client dials and holds the keys of every
destination the gateway mints for it, so turning it on is an explicit choice.

The wire is specified in `PROTOCOL.md`, which is the authority for anything this
README says loosely.

## What the operator sees

- every destination a client dials, and every address it publishes
- the keys of every destination the gateway mints, because it mints them
- the timing and the volume of all of that client's I2P traffic
- the client's IP address

Not: account identity keys, the profile database, message content (encrypted end
to end above this layer), or the master key of an account's serving destination.

## Building

```
cmake -S . -B build
cmake --build build -j4
ctest --test-dir build
```

Requires CMake >= 3.20, C++20, OpenSSL >= 3.0. `common` is a git submodule:

```
git submodule update --init --recursive
```

## Deploying

The daemon speaks HTTP on a socket of its own; TLS, the public address and the
cover site are the front's (nginx, Caddy). The front is whatever the operator
wants - a real site, a holding page, a `proxy_pass` to somebody else's site
entirely - and the gateway occupies one unguessable path on it.

Getting in needs **both** the secret path and the token in `X-Bazarish-Gateway`.
The wrong path, the right path with no token and the right path with a wrong
token all get the same 404, from the same template, in the same time: a 404 that
arrives faster when the path happens to be right is an oracle, and an oracle
turns a secret path into a search.

Checking the token at the front as well is recommended - it keeps unauthorised
requests off the daemon entirely - but it is a recommendation. The gateway is
answerable for its own admission and behaves the same whether or not anyone
took it.
