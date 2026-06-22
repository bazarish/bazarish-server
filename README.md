# bazarish-admin-panel

A single web interface to monitor and manage the Bazarish fleet (server-core,
service-node, blob-storage, facade-http, alias-resolver).

## Authentication

Access is gated to **one** Bazarish identity. There are no passwords and no
account database: the operator pastes their own fingerprint into the config, and
logging in is done by signing a challenge with the client.

1. Read your fingerprint: `bazarish-client whoami <state>` and put it in the
   config `admin` field.
2. Open `/login`; the page shows a challenge.
3. Sign it in your client: `bazarish-client sign-login <state> <challenge>`.
4. Paste the resulting blob back. The panel verifies the hybrid signature
   **locally** against the configured admin fingerprint and starts a session.

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
bazarish-blob-storage ... --operator-fingerprint <panel-fp> --operator-fingerprint <service-node-fp>
bazarish-service-node ... --operator-fingerprint <panel-fp>
bazarish-facade-http  ... --operator-fingerprint <panel-fp>
bazarish-alias-resolver ... --operator-fingerprint <panel-fp>
```

(The service node also signs its own quota/transient pushes, so the storage
backends authorise both the panel and the service node.)

## Status and management

- **Status:** the dashboard probes each configured service's signed
  `GET /healthz` (service name, version, uptime, current and peak RAM) and shows
  it live, with latency.
- **Management:** the panel drives the operator endpoints the services already
  expose - set a user's storage quota (server-core, blob-storage) and
  provision/revoke a user's personal I2P destination (server-core).

The panel is a co-located operations tool. It reaches services on their private
listen addresses; `/healthz` and the operator endpoints are not exposed through
the facade or over I2P.

## Configuration

See `config.example.json`: the authorised admin fingerprint, the listen address,
and the list of services (name, kind, url) - no secrets.

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
