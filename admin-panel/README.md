# bazarish-admin-panel

A single web interface to monitor and manage the Bazarish fleet (server-core,
service-node, facade-http, alias-resolver).

## Authentication

Access is gated to **one** Bazarish identity. There are no passwords and no
account database: the operator pastes their own fingerprint into the config, and
logging in is done by signing a challenge with the client.

1. Read your fingerprint: `bazarish-client whoami <profile>` and put it in the
   config `admin` field.
2. Open `/login`; the page shows a challenge.
3. Sign it in your client: `bazarish-client sign-login <profile> <challenge>`.
4. Paste the resulting blob back. The panel verifies the hybrid signature
   **locally** against the configured admin fingerprints and starts a session.

The login needs no backend online - the panel is the verifier. The challenge is
single-use and bound to this panel's audience, so a login blob captured anywhere
else cannot be replayed here.

## Talking to services: identity-signed, no shared secrets

The panel has its own Bazarish identity, generated on first start in `<state>`. It
**signs every service call** (health probes and operator actions) with that
identity, exactly like every other request in the system. Each service authorises
the panel by fingerprint: start each service with the panel's fingerprint (printed
at panel startup) as an `--operator-fingerprint`. There is no shared secret.

```
bazarish-server      ... --operator-fingerprint <panel-fp> --operator-fingerprint <service-node-fp>
bazarish-service-node ... --operator-fingerprint <panel-fp>
bazarish-facade-http  ... --operator-fingerprint <panel-fp> --ops-listen 127.0.0.1 8429
```

(The service node also signs its own quota/transient pushes, so server-core
authorises both the panel and the service node.)

## What it shows

A sidebar with two views, drawn by a small script from the panel's own JSON API:

- **Monitoring** - every configured service probed concurrently through its
  signed `GET /healthz` (name, version, uptime, current and peak RAM, latency),
  re-probed every few seconds.
- **Users** - the accounts on the service node: search by fingerprint (the node
  does the searching), filter by approval state, open an account to read its
  terms, set its storage quota in megabytes, or approve it.

The sign-in page needs no JavaScript, so a fleet that is entirely down can still
be logged into. The panel's web files live in `--assets <dir>` (`web/` in this
repository) - edit them to restyle the panel, then restart it.

The panel is a co-located operations tool. It reaches services on their private
listen addresses; `/healthz` and the operator endpoints are not exposed through
the facade or over I2P. The facade's own `/healthz` is on the private socket it
opens with `--ops-listen`, never on its client-facing one - there it would answer
a caller who does not know the secret base path - so the panel is configured with
that ops address, not with the published facade URL.

## Configuration

See `config.example.json`: the authorised admin fingerprints (one string or a
list), the listen address, and the deployments it manages - no secrets. Each
deployment is a `server-core`, the `service-node` bound to it and its facades;
several can be listed, and the account views act on the one chosen in the
sidebar. The alias service is not here: it is one central service for the whole
project, not part of an operator's server.

## Build & test

```bash
cmake -S . -B build && cmake --build build -j
ctest --test-dir build
```

Requires CMake >= 3.20, C++20, OpenSSL >= 3.0. Uses the shared `common` library
(git submodule at `./common`, or a sibling `../common` checkout in the workspace).

## Run

```bash
bazarish-admin-panel --config config.json
```

The config is the only thing on the command line: the state directory, the web
files, the listen address and the services all live in it, so there is never a
question of which of two answers won.

```
```
