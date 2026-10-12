# bazarish-gateway

A host that runs the I2P router for a Bazarish client, so the client does not.
The client switches its own router off and reaches this over one pinned-TLS
WebSocket per flow; nothing above the transport changes.

The operator sees every destination its clients dial and holds the keys of the
destinations it mints for them. `PROTOCOL.md` is the authority for the wire and
for what that trust covers.

A gateway is an optional part of a server deployment. Nothing in the deployment
depends on it, and it needs nothing from the deployment: it runs from its own
file alone. The admin panel only watches and tunes it, over `opsListen`.

## Building

It builds with the rest of the server fleet (the repository's own README), or on
its own:

```
cmake -S gateway -B build-gateway
cmake --build build-gateway -j4
ctest --test-dir build-gateway
```

## Configuring

One file, given with `--config`. `config.example.json` is a starting point.

| Key | What it sets |
|---|---|
| `listen` | Host and port. The front reaches it here; clients never do |
| `basePath` | The path the gateway answers at. Mandatory |
| `token` | The token every request to that path must carry. Mandatory |
| `state` | Where the router keeps its netDb, keys and tunnels |
| `reseed` | su3 archives a router with no peers starts from. Empty leaves the engine its built-in hosts |
| `decoy.minBytes`, `decoy.maxBytes` | The length of a decoy answer, drawn between them |
| `sessionTtlSeconds` | How long a session outlives its last socket |
| `i2p.privacy`, `i2p.tunnelQuantity` | How long the tunnels of every client's destinations are and how many each keeps: one setting for everyone, since a client on a gateway sets none. `minimal` and 3 unless given; call media is always one hop |
| `pools.stream`, `pools.call` | How many destinations are kept built ahead of asking: unpublished stream destinations with the tunnels above, and call-media destinations. 4 and 2 unless given, at most 16; 0 builds every one on demand |
| `direct` | Destinations this gateway reaches without I2P: `dest`, the `host` and `port` serving it, and the `pin` that address presents |
| `opsListen` | A TLS socket for the admin panel, answering only the keys in `opsClients`: health, settings and restart. Left out, there is no such socket, and the file is edited by hand |
| `opsClients` | The keys allowed to open that socket: the panel prints its own |
| `operators` | Fingerprints allowed to use that socket |
| `serverName` | The `Server` header on the 404 |
| `notFound` | A file whose contents are that 404. Empty serves nginx's own page |

Make the path and the token from the system's random source, and keep the file
to the daemon:

```
head -c 18 /dev/urandom | base64 | tr -d '=+/' | head -c 24    # basePath
head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 43    # token
chmod 600 /etc/bazarish/gateway.json
```

## The front

The daemon speaks HTTP on its own socket. TLS, the public address and the cover
site belong to the front it listens behind, and that front can be anything - a
site, a holding page, a `proxy_pass` to somebody else's.

A request without the token falls through to the cover, so the secret path
answers exactly like every other path on the host. Checking the token at the
front as well keeps unauthorised requests off the daemon; the gateway answers
for its own admission either way.

```nginx
map $http_upgrade $upgrade { default upgrade; "" close; }

server {
    server_name gateway.example;

    location = /<basePath> {
        if ($http_x_bazarish_gateway != "<token>") { return 418; }
        error_page 418 = @cover;
        proxy_pass http://127.0.0.1:8431;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $upgrade;
        proxy_read_timeout 3600s;
    }
    location / { proxy_pass https://cover.example; }
    location @cover { proxy_pass https://cover.example; }
}
```

## Giving someone the address

One string carries both halves of getting in:

```
https://gateway.example/<basePath>#<token>
```

The client takes it in its settings and checks it before keeping it.

## Health

`GET /healthz` on the `opsListen` socket, with a signature from a fingerprint in
`operators`, answers the fleet's health report plus what this gateway holds:
sessions, destinations, streams, sockets, rejoins and refusals. That socket
admits only the keys in `opsClients`, which is how the admin panel reaches it.
The public listener has no health path: `<basePath>/healthz` is the same 404 as
anything else, so a scan learns nothing from it. Without `opsListen` there is no
health report; the log says when the router has its tunnels.

## Settings and restart

The same socket, with the same signature, carries `GET`/`PUT /settings` and
`POST /restart`. `/settings` shows and writes into the config file the tunnels
(`i2pPrivacy`, `i2pTunnelQuantity`), the two pools (`streamPool`, `callPool`) and
the `direct` routes; it never shows the path or the token. Direct routes apply
at once; the tunnels and the pools at the next start, since the pools are built
then. `POST /restart` exits with code 90, which a unit with `Restart=on-failure`
brings back.
