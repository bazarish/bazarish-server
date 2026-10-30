# Bazarish - server-core

The messaging server for the [Bazarish](https://github.com/bazarish/docs-main)
messenger: pending content storage, the delivery pipeline and server-to-server
federation over hidden networks.

The server has **no public IP interfaces** - its only public presence is in I2P,
and nothing else is spoken. Clients never talk to it directly; they reach it
through the facade (`facade-http` in this repository) over an operator-controlled
private channel. The server sees only ciphertext: message
payloads are end-to-end encrypted by clients, and the delivery metadata is
sealed to the server's sealing key.

## What it does

- **Delivery engine** - unseal the envelope, dedup by deliveryId, spend the
  delivery pass it presents (or admit a contact request, which presents none and
  is rate-limited for it), enforce size and quota, store. Mail is limited per
  pass, 120 a minute. A contact request is admitted once per sending address:
  the server keeps a hash of that address for a day and refuses the next request
  from it, since a client sends every request from an address of its own. It admits on the
  envelope alone, whoever dialled.
- **Storage** - per-user client registry, the passes an account has issued, and
  pending blobs. Content is deleted as soon as every registered client has acked
  it, and otherwise when the account goes: a mailbox nobody collects is the
  client's business, and the quota is what bounds it.
- **HTTP API** - one route a facade can see: the sealed tunnel every client
  request travels inside, carrying `/v1/messaging/*` (client registry, passes and
  their revocation, pending fetch/ack, the write a device makes into its own
  account's mailbox) and the account calls this server forwards to the service
  node under its own signature. There is no send endpoint: a client delivers its
  own outgoing mail, so this server is never told whom its users write to.
- **Federation** - serves **each user's own destination** over I2P; there is no
  destination for the server as a whole. It admits what arrives and signs its
  confirmation with that destination's own key.

## Build

Requires CMake >= 3.20, C++20, OpenSSL >= 3.5. `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/bazarish-server
cmake -S bazarish-server -B build && cmake --build build -j4
ctest --test-dir build
```

## Run

```
bazarish-server --config <path>
```

One flag and no others: everything is in that file (see
`config.example.json`) - the state directory, the addresses it listens on, the
operators who may call its operator endpoints, the service node beside it, and
the I2P settings. Keys are generated in the state directory on first start and
the server card is written there as `server-card.der` (its sealing key and
transport endpoints).

Both sockets speak TLS, with a certificate this server makes in its state
directory on first start; the hash of its key is printed at startup and is what
a peer is configured with. `listen` carries the sealed tunnel and federation,
which the facade forwards to. `opsListen` carries everything that is the
operator's - health, settings, restart, quotas, destinations, the service node's
card signed with this server's root, the reseed archive the portal serves - and
admits only a certificate listed in `opsClients`: the
admin panel's and the service node's. The node beside it is named the same way,
`"serviceNode": {"url": "https://...", "pin": "..."}`, and the pin is not
optional: without one the dial is refused rather than trusted.

`gatewayListen` is optional and serves the gateways of the same operator, each
admitted by the key listed for it in `gateways`. A gateway learns there every
destination this server serves and carries its users' streams to them without
I2P (`gateway/PROTOCOL.md`, The server link). The admin panel writes both.

The I2P router is **in this process**: `common` carries the engine, so there is
no daemon to install and no SAM bridge to run beside it.
