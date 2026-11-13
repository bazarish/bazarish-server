# Bazarish - gateway

A host that runs the I2P router for a Bazarish client, so the client does not.
The client switches its own router off and reaches this over one WebSocket per
flow, in a channel sealed to the gateway's own key; nothing above the transport
changes.

The operator sees every destination its clients dial and holds the keys of the
destinations it mints for them. `PROTOCOL.md` is the authority for the wire and
for what that trust covers.

A gateway is an optional part of a server deployment. Nothing in the deployment
depends on it, and it needs nothing from the deployment: it runs from its own
file alone. The admin panel only watches and tunes it, over `opsListen`.

## Building

It builds with the rest of the server components (the repository's own README), or on
its own:

```
cmake -S gateway -B build-gateway
cmake --build build-gateway -j4
ctest --test-dir build-gateway
```

On Debian 13 the gateway is also a package of its own, `bazarish-gateway`. Its
first install writes `/etc/bazarish/gateway.json` with a fresh path and starts
the daemon.

## Configuring

One file, given with `--config`. `config.example.json` is a starting point.
These keys are all it reads: a key it does not know, at the top or inside a
section, stops it at start with an error that names the key.

| Key | What it sets |
|---|---|
| `listen` | Host and port. The front reaches it here; clients never do |
| `basePath` | The path the gateway answers at. Mandatory |
| `publicAddress` | Where the front answers clients, `http(s)://host[:port]` with no path; the host may be an IPv4 or `[IPv6]` address. Only builds the link the admin panel shows |
| `state` | Where the router keeps its netDb, keys and tunnels, and the gateway its own identity and sealing key |
| `reseed` | su3 archives a router with no peers starts from. Empty leaves the engine its built-in hosts |
| `decoy.page`, `decoy.resource` | The length of a decoy answer, for a page and for a resource (asked with `?fast=true`): `maxBytes` and a list of `parts`, each a log-normal of `weight`, `medianBytes` and `sigma`. Every median lies between 1 and `maxBytes`. Unset: a page of median 30 KiB and sigma 1.0, a resource of median 15 KiB and sigma 1.5, both at most 1 MiB |
| `sessionTtlSeconds` | How long a session outlives its last socket |
| `i2p.privacy` | How long the tunnels of every client's destinations are: one setting for everyone, since a client on a gateway sets none. `minimal` unless given. Each destination keeps three tunnels each way, the client's own count, and that is not a setting; call media is always one hop and six tunnels each way, its path picked by measured round trip |
| `pools.stream`, `pools.call`, `pools.watch` | How many destinations are kept built ahead of asking: unpublished stream destinations with the tunnels above, call-media destinations, and published datagram destinations for watching presence. 4, 2 and 2 unless given, at most 16; 0 builds every one on demand |
| `server` | The server-core this gateway is linked to: the `host` and `port` of its `gatewayListen` and the `pin` it presents. Every destination it serves is then reached without I2P. Written by the admin panel; left out, there is no link |
| `direct` | The facades reached without I2P: `dest`, the `host` and `port` of the facade's `directListen`, and the `pin` it presents. Written by the admin panel |
| `opsListen` | A TLS socket for the admin panel, answering only the keys in `opsClients`: health, settings and restart. Left out, there is no such socket, and the file is edited by hand |
| `opsClients` | The keys allowed to open that socket: the panel prints its own |
| `operators` | Fingerprints allowed to use that socket |
| `logLevel`, `i2p.logLevel` | The daemon's log level (`error`, `warn`, `info` or `debug`; `info` unless given) and the router's (`none`, `error`, `warn`, `info` or `debug`; `none` unless given) |
| `serverName` | The `Server` header on the 404 |
| `notFound` | A file whose contents are that 404. Empty serves nginx's own page |

Make the path from the system's random source, and keep the file to the daemon:

```
head -c 18 /dev/urandom | base64 | tr -d '=+/' | head -c 24    # basePath
chmod 600 /etc/bazarish/gateway.json
```

The gateway makes its identity and sealing key in `state` on its first start and
logs its fingerprint; the link carries that fingerprint.

## The front

The daemon speaks HTTP on its own socket. TLS, the public address and the cover
site belong to the front it listens behind, and that front can be anything - a
site, a holding page, a `proxy_pass` to somebody else's. TLS is cover only: the
client does not check the certificate, the channel inside the socket is what
proves the gateway, so a self-signed certificate or plain `http` on an address
serves as well. The certificate's key is ECDSA or RSA: the client's handshake is
Chrome's, which offers no Ed25519. The front speaks HTTP/1.1 on this host, with
HTTP/2 off (in nginx no `http2 on` and no `listen ... http2` on its address): a
client offers `h2` on decoy connections, as Chrome does, and refuses a front that
chooses it.

```nginx
map $http_upgrade $upgrade { default upgrade; "" close; }

server {
    server_name gateway.example;

    location = /<basePath> {
        proxy_pass http://127.0.0.1:8431;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $upgrade;
        proxy_read_timeout 3600s;
    }
    location / { proxy_pass https://cover.example; }
}
```

## Giving someone the address

One Bazarish link carries where the gateway is and which key it holds:

```
https://bazari.sh/#gateway?v=1&url=https://gateway.example<basePath>&fp=<fingerprint>
```

The client takes it in its settings, or from a message: tapping the link asks
before putting the gateway into the settings, and the client checks it before
keeping it. With `publicAddress` set (`https://gateway.example`, no path), the
admin panel shows this link for the gateway.

## Health

`GET /healthz` on the `opsListen` socket, with a signature from a fingerprint in
`operators`, answers the common health report plus what this gateway holds:
sessions, destinations, streams, sockets, rejoins and refusals. That socket
admits only the keys in `opsClients`, which is how the admin panel reaches it.
The public listener has no health path: `<basePath>/healthz` is the same 404 as
anything else, so a scan learns nothing from it. Without `opsListen` there is no
health report; the log says when the router has its tunnels.

Each client socket the gateway closes for what the client sent - a record that
does not open, an opening that is neither a hello nor a join, a frame that does
not read, a version it does not speak, a second hello, a socket of no session, a
full session - is one `warn` line with the reason. The line names no address, no
path and no key.

## Settings and restart

The same socket, with the same signature, carries `GET`/`PUT /settings` and
`POST /restart`. `/settings` shows and writes into the config file the log level
(`logLevel`: `error`, `warn`, `info` or `debug`, `info` when the file names
none), libi2pd's lines in that log (`i2pLogLevel`, written as `i2p.logLevel`:
`none`, `error`, `warn`, `info` or `debug`, `none` when the file names none),
the tunnels (`i2pPrivacy`), the three pools (`streamPool`, `callPool`,
`watchPool`), the `server` link and the `direct` routes; it never shows the
path. The two log levels, the link and the routes apply at once; the tunnels and the
pools at the next start, since the pools are built then. `POST /restart` exits
with code 90, which a unit with `Restart=on-failure` brings back.

`GET /logs?after=N` on the same socket answers the log lines this process wrote
after line N, as server-core's `/v1/messaging/logs` does.
