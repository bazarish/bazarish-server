# Bazarish - server-core

The messaging server for the [Bazarish](https://github.com/bazarish/docs-main)
messenger: pending content storage, the delivery pipeline and server-to-server
federation over hidden networks.

The server has **no public IP interfaces** - its only public presence is in
hidden networks (I2P first). Clients never talk to it directly; they reach it
through a [facade](https://github.com/bazarish/facade-http) over an
operator-controlled private channel. The server sees only ciphertext: message
payloads are end-to-end encrypted by clients, and the delivery metadata is
sealed to the server's sealing key.

## What it does

- **Delivery engine** - unseal the envelope, dedup by deliveryId, consume a
  one-time delivery token (or admit a contact request), enforce size/quota,
  store. It admits on the envelope alone, whoever dialled.
- **Storage** - per-user client registry, token-hash sets and pending blobs.
  Content is deleted as soon as every registered client has acked it.
- **HTTP API** - `/v1/messaging/*`: client registry, token hashes, pending
  fetch/ack, and the write a device makes into its own account's mailbox. There
  is no send endpoint: a client delivers its own outgoing mail, so this server is
  never told whom its users write to.
- **Federation** - serves each user's destination over I2P: it admits what
  arrives and signs its confirmation into the reply. It dials out only for
  discovery (a contact-card or alias lookup on a client's behalf).

## Build

Requires CMake >= 3.20, C++20, OpenSSL >= 3.0. `common` is a submodule.

```bash
git clone --recurse-submodules https://github.com/bazarish/server-core
cmake -S . -B build && cmake --build build -j
ctest --test-dir build
```

## Run

```
bazarish-server --state <dir> [--listen <host> <port>]
                [--i2p] [--federation-listen <host> <port>]
                [--contact-request-limit <bytes>]
```

Keys are generated in `<dir>` on first start and the server card is always
written to `<dir>/server-card.der` (its sealing key and transport endpoints).
`--i2p` adds the I2P endpoint and enables I2P federation (needs a local SAM
bridge); `--federation-listen` enables a plain-TCP federation transport for an
operator private channel. Outbound federation resolves peers from
`<dir>/peers.json` (`{"<server-fingerprint>": "<i2p-destination-or-host:port>"}`).
