# Bazarish - server-service

Account management for the [Bazarish](https://github.com/bazarish/docs-main)
messenger, kept as a separate process from the messaging logic: who has an
account here, what their destination is, and what they are allowed.

A server service is bound to one messaging server by its node card, which that
server signs over their pinned link at every start; the card names the server
fingerprint an account's card must name.
Authenticated requests carry the caller's hybrid identity, and a caller may only
act on its own account.

An alias belongs to `alias-resolver`, which is a service of its own.

## What it does

- **Registration**, in one of two modes. Open: proving a key is the
  registration, whether it is proven in the portal or by a client calling
  `POST /v1/account/registration`. Moderated (`registration.requireApproval`):
  the account is created the same way and waits for an operator, which the client
  learns as `ACCOUNT_PENDING_APPROVAL`. An account lives while its owner keeps a destination delegated here, and an idle one is swept
  after `registration.idleDeleteDays`.
- **The user's own destination.** `POST /v1/account/i2p-dest` takes the offline
  transient that lets the messaging server operate the address and answers with
  the `{dest, servingKey}` that destination now serves under, so the client can
  issue its card from that one answer; `i2p-status`
  says how long the current one lasts so any device knows when to issue the next,
  and with `hold=1&since=<approval>` holds the request until the account is
  approved, declined or banned, or for the hold the device names in `wait`
  (`docs-main/api/ClientApi.md`);
  `undelegate` takes an account out of service without deleting it. A transient
  over a different address replaces the destination outright - the old one is
  stopped and dropped in the same call, with no grace period.
- **The contact card.** `POST /v1/account/card` stores the user-signed card and
  is what redeems a registration into an account. `GET /v1/account/card?user=`
  hands it back to whoever reached this account's destination, which is the only
  way in: the address itself is the secret.
- **Quota.** This server service grants it, stores it and pushes it to the messaging
  server, which would otherwise keep serving its own default.
- **What the messaging server has not confirmed.** A changed quota, a new
  card, an address taken down by `undelegate` or a deleted account - by its
  owner, by the operator, by a ban or by the idle sweep - is first marked
  unsent in `state/store/unsent/<user>.json`, then pushed. A delegation the
  messaging server accepts afterwards replaces a takedown still marked. A
  deleted account's mark has the messaging server drop its mailbox and its
  address, and goes before anything else marked for that user; a delegation is
  refused with 503 while it is still marked. The server service reads every mark at
  start and refuses to start, naming the file, when one does not name all four.
  The mark names what is due, not a value: a push always carries what the
  account record holds at that moment. A push that fails leaves the mark, and
  the change still answers 200, because it is made on this server service; the account
  then reads `serverPending: true` on the operator's face. Marks are pushed
  again when the messaging server is known to answer: any answer to a call this
  server service makes to it, including the health check at start, and any signed request
  the messaging server sends here. There is no timer and no repeat on failure.
- **The operator's face**: on a socket of its own (`opsListen`, TLS, answering
  only the keys in `opsClients`): listing and searching accounts, ban/unban,
  approve, live settings, a restart request and the log
  (`GET /v1/account/logs?after=N`, answered as server-core's
  `/v1/messaging/logs`) - all signed with an identity, and what `admin-panel`
  drives.

## Build

Requires CMake >= 3.20, C++20, OpenSSL >= 3.5 and libqrencode (`libqrencode-dev`). `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/bazarish-server
cmake -S bazarish-server -B build && cmake --build build -j4
ctest --test-dir build
```

## Run

```
bazarish-server-service --config <path>
```

Everything the server service runs on is in that file (see `config.example.json`): its
state directory, the addresses it listens on and reaches, the
operator fingerprints, and what new accounts get. There are no value flags - one
place to look, one place to change - and the admin panel edits the same file one
value at a time, leaving the rest of it, comments included, untouched.

A client reaches this server service through the facade (`facade-http` in this repository)
in a sealed tunnel of the server service's own, `POST /n`, opened under the key in the server service
card, `GET /v1/node/card`. The server service makes that key in `state`; at every start the
messaging server signs the card with its root, so a client checks it against the
same fingerprint as the server card, and the server service does not start without it. The
server service asks for the card once; a messaging server that does not answer stops the
start, with the cause in the log. The packaged messaging server tells systemd it is
ready once it listens, and the server service's unit is ordered after it, so at boot the server service
asks a server that already answers.

`listen` and `opsListen` both speak TLS, with a certificate this server service makes in
its state directory on first start; the hash of its key is printed at startup
and is what a peer is configured with. `listen` is what the facade and the
messaging server reach. `opsListen` carries the operator's face and admits only
a certificate listed in `opsClients`, which is the admin panel's. What this server service
asks of the messaging server - quotas, destinations, a deleted mailbox, the
reseed archive the portal publishes - goes to that server's operator socket:
`"messaging": {"host": ..., "port": ..., "pin": ...}`, signed with this server service's
identity and presenting this server service's certificate, which the messaging server
lists in its own `opsClients`.

`portal.listen` opens the browser-facing portal: one JS-free page where a user
proves their key, which is the whole registration. It also publishes this
server's reseed archive at `i2pseeds.su3`, because a client needs that before it
has I2P and so cannot ask a facade for it.
`portal.assets` points at the portal's web files (`portal/` in this
repository: page shell, stylesheet, logo, fonts) - edit them to restyle the
portal without rebuilding. They are read once and served from memory, so a
change takes effect on restart.
