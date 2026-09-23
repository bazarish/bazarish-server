# bazarish-gateway

A host that runs the I2P router for a Bazarish client, so the client does not.
The client switches its own router off and reaches this over one pinned-TLS
WebSocket per flow; nothing above the transport changes.

The operator sees every destination its clients dial and holds the keys of the
destinations it mints for them. `PROTOCOL.md` is the authority for the wire and
for what that trust covers.

## Building

```
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j4
ctest --test-dir build
```

CMake >= 3.20, C++20, OpenSSL >= 3.0.

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
| `operators` | Fingerprints allowed to read the health report |
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

`GET <basePath>/healthz`, with the token and a signature from a fingerprint in
`operators`, answers the fleet's health report plus what this gateway holds:
sessions, destinations, streams, sockets, rejoins and refusals. Without the
token it is the same 404 as anything else, so a scan learns nothing from the
path.
