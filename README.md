# Bazarish — service-node

User management for the [Bazarish](https://github.com/bazarish/docs-main)
messenger, kept as a separate process from the messaging logic: subscriptions,
aliases and first-contact lookup.

A service node is bound to one messaging server by that server's card (passed
at startup), from which it takes the server fingerprint that subscription
certificates must name. Authenticated requests carry the caller's hybrid
identity; a caller may only act on certificates naming its own UID.

## What it does

- **Subscriptions** — verifies and stores user-signed subscription
  certificates (hybrid signature, names this server, unexpired, within the max
  term); renewal is a fresh certificate. Returns quota and the server card.
- **Aliases** — registers user-signed nickname certificates; `ALIAS_TAKEN`
  when owned by another user.
- **Resolution** — `GET /v1/account/resolve?alias=X` returns the alias trust
  chain; `GET /v1/account/contact?user=X` returns a user's subscription
  certificate, which carries the serving server and the sealing **prekey** a
  first-contact sender uses to E2E-encrypt the contact request.

## Build

Requires CMake ≥ 3.20, C++20, OpenSSL ≥ 3.0. `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/service-node
cmake -S . -B build && cmake --build build -j
ctest --test-dir build
```

## Run

```
bazarish-service-node --state <dir> --server-card <path> [--listen <host> <port>]
```

The server card is produced by the messaging server and binds this node to it.
The service node sits behind a [facade](https://github.com/bazarish/facade-http),
which routes `/v1/account/*` to it.
