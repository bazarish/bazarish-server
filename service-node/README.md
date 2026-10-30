# Bazarish - service-node

Account management for the [Bazarish](https://github.com/bazarish/docs-main)
messenger, kept as a separate process from the messaging logic: who has an
account here, what their destination is, and what they are allowed.

A service node is bound to one messaging server by that server's card (passed at
startup), from which it takes the server fingerprint a card must name.
Authenticated requests carry the caller's hybrid identity, and a caller may only
act on its own account.

Names are not this node's business: an alias belongs to `alias-resolver`, which
is a service of its own and is not reached through here.

## What it does

- **Registration**, in one of two modes and no third. Open: proving a key is the
  registration, whether it is proven in the portal or by a client calling
  `POST /v1/account/registration`. Moderated (`registration.requireApproval`):
  the account is created the same way and waits for an operator, which the client
  learns as `ACCOUNT_PENDING_APPROVAL`. An account has **no term** - it lives
  while its owner keeps a destination delegated here, and an idle one is swept
  after `registration.idleDeleteDays`.
- **The user's own destination.** `POST /v1/account/i2p-dest` takes the offline
  transient that lets the messaging server operate the address and answers with
  the `{dest, servingKey}` that destination now serves under, so the client can
  issue its card from one answer instead of asking again; `i2p-status`
  says how long the current one lasts so any device knows when to issue the next;
  `undelegate` takes an account out of service without deleting it. A transient
  over a different address replaces the destination outright - the old one is
  stopped and dropped in the same call, with no grace period.
- **The contact card.** `POST /v1/account/card` stores the user-signed card and
  is what redeems a registration into an account. `GET /v1/account/card?user=`
  hands it back to whoever reached this account's destination, which is the only
  way in: the address itself is the secret.
- **Quota.** This node grants it, stores it and pushes it to the messaging
  server, which would otherwise keep serving its own default.
- **The operator's face**: on a socket of its own (`opsListen`, TLS, answering
  only the keys in `opsClients`): listing and searching accounts, ban/unban,
  approve, live settings and a restart request - all signed with an identity, and
  what `admin-panel` drives.

## Build

Requires CMake >= 3.20, C++20, OpenSSL >= 3.5 and libqrencode (`libqrencode-dev`). `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/bazarish-server
cmake -S bazarish-server -B build && cmake --build build -j4
ctest --test-dir build
```

## Run

```
bazarish-service-node --config <path>
```

Everything the node runs on is in that file (see `config.example.json`): its
state directory, the server card, the addresses it listens on and reaches, the
operator fingerprints, and what new accounts get. There are no value flags - one
place to look, one place to change - and the admin panel edits the same file one
value at a time, leaving the rest of it, comments included, untouched.

The server card is produced by the messaging server and binds this node to it.
A client reaches this node through the facade (`facade-http` in this repository)
in a sealed tunnel of the node's own, `POST /n`, opened under the key in the node
card, `GET /v1/node/card`. The node makes that key in `state`; at every start the
messaging server signs the card with its root, so a client checks it against the
same fingerprint as the server card, and the node does not start without it.

`listen` and `opsListen` both speak TLS, with a certificate this node makes in
its state directory on first start; the hash of its key is printed at startup
and is what a peer is configured with. `listen` is what the facade and the
messaging server reach. `opsListen` carries the operator's face and admits only
a certificate listed in `opsClients`, which is the admin panel's. What this node
asks of the messaging server - quotas, destinations, a deleted mailbox, the
reseed archive the portal publishes - goes to that server's operator socket:
`"messaging": {"host": ..., "port": ..., "pin": ...}`, signed with this node's
identity and presenting this node's certificate, which the messaging server
lists in its own `opsClients`.

`portal.listen` opens the browser-facing portal: one JS-free page where a user
proves their key, which is the whole registration. It also publishes this
server's reseed archive at `i2pseeds.su3`, because a client needs that before it
has I2P and so cannot ask a facade for it.
`portal.assets` points at the portal's web files (`portal/` in this
repository: page shell, stylesheet, logo, fonts) - edit them to restyle the
portal without rebuilding. They are read once and served from memory, so a
change takes effect on restart.
