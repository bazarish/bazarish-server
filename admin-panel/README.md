# bazarish-admin-panel

A single web interface to monitor and manage the Bazarish fleet: `server-core`,
`service-node`, the facade and a private gateway.

## Authentication

Access is restricted to the configured Bazarish identities. There are no passwords
and no account database: the operator places their own fingerprint in the
configuration, and signing in consists of signing a challenge with the client.

1. Take the account's fingerprint from the client (its signature window shows it)
   and enter it in the configuration field `admin`.
2. Open `/login`; the page presents a challenge.
3. Sign the challenge in the client, which is where the key is.
4. Submit the resulting blob. The panel verifies the hybrid signature **locally**
   against the configured admin fingerprints and starts a session.

Signing in requires no backend to be running: the panel performs the
verification. The challenge is single-use and names this panel - the words your
client shows you before signing - so a login blob captured anywhere else cannot
be replayed here, and a challenge from anywhere else is visibly not this panel.

By default the panel calls itself "Bazarish admin panel" (plus the fleet name,
when the config names one) at the address it listens on. Front it behind a name
of your own and the address you open no longer matches what your client shows:
set `consumer` in the config to the words you want compared.

## Talking to services: identity-signed, no shared secrets

The panel has its own Bazarish identity, generated on first start in `<state>`. It
**signs every service call** (health probes and operator actions) with that
identity, exactly like every other request in the system. Each service authorises
the panel by fingerprint: put the panel's fingerprint (printed at panel startup)
in that service's `"operators"` list. There is no shared secret.

The service node also signs its own quota and transient pushes, so server-core's
list carries both the panel and the service node.

The transport underneath is TLS both ways. Every service makes a certificate of
its own on first start and prints the hash of its key; the panel is configured
with that hash per service and accepts no other, and the service's operator
socket accepts only the key the panel presents, which it prints the same way. A
service URL that is not `https://`, or one with no key named, refuses to load.
Nothing about who may call what moves into the certificates: that is still the
signature and the `"operators"` list. What the certificates add is that the two
sockets know each other, which is what lets them be on different machines.

## What it shows

A sidebar with two views, drawn by a small script from the panel's own JSON API:

- **Monitoring** - every configured service probed concurrently through its
  signed `GET /healthz` (name, version, uptime, current and peak RAM, latency),
  re-probed every few seconds.
- **Users** - the accounts on the service node: search by fingerprint (the node
  does the searching), filter by approval state, open an account to read its
  terms, set its storage quota in megabytes, or approve it.

The sign-in page needs no JavaScript, so a fleet that is entirely down can still
be logged into. The panel's web files live where the config's `assets` points (`web/` in this
repository) - edit them to restyle the panel, then restart it.

Every service keeps the operator's endpoints on a socket of its own, the one
its `opsListen` opens, and the panel is configured with that address rather than
the one clients reach. Nothing an operator asks for is on a client-facing socket:
on the facade any of it would admit a facade is there to a caller who does not
know the secret base path, and the same reasoning holds for the rest. Because
the link is pinned TLS in both directions, those sockets do not have to be on
this host - a fleet can sit on several machines without a tunnel between them.

## Configuration

See `config.example.json`: the authorised admin fingerprints (one string or a
list), the listen address, and the deployments it manages - no secrets. Each
deployment is a `server-core`, the `service-node` bound to it and its facades;
several can be listed, and the account views act on the one chosen in the
sidebar. The alias service is not here: it is one central service for the whole
project, not part of an operator's server.

## Build & test

```bash
cmake -S bazarish-server -B build && cmake --build build -j4
ctest --test-dir build
```

Requires CMake >= 3.20, C++20, OpenSSL >= 3.5. Uses the shared `common` library
(the repository's submodule at `./common`).

## Run

```bash
bazarish-admin-panel --config config.json
```

The config is the only thing on the command line: the state directory, the web
files, the listen address and the services all live in it, so there is never a
question of which of two answers won.
