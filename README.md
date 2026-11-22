# Bazarish server

Every server-side component of Bazarish in one build tree. The protocol they
implement is specified in the `docs-main` repository; the desktop client
(`client-qt`), the alias service (`alias-resolver`) and the shared library
(`common-cpp`) live in their own repositories.

| Directory | Binary | Role |
|---|---|---|
| `server-core` | `bazarish-server-core` | message delivery, mailboxes, federation over I2P |
| `server-service` | `bazarish-server-service` | registration, accounts, the browser portal |
| `facade-http` | `bazarish-facade-http` | the client-facing last mile: a sealed tunnel, forwarded blind |
| `admin-panel` | `bazarish-admin-panel` | operator UI, authenticated by identity signature |
| `gateway` | `bazarish-gateway` | optional: runs the I2P router for clients that do not run their own |
| `setup` | `bazarish-setup` | the package's first install: every config, linked by the keys it makes |
| `common` | - | submodule of `common-cpp`: crypto, I2P transport, embedded i2pd |

The gateway is the one optional component: nothing else here depends on it, and
it needs nothing from the rest.

The components stay separate processes and separate deployment units - a facade
compromise still must not reach the server. They reach each other over TLS,
pinned by the key each one prints when it starts, so the services can be spread over
several machines without a tunnel between them. The shared repository gives
them one `common` submodule and one build of the embedded I2P router.

Every component takes exactly one flag: `--config <path>`. Values live in that
file (JSON, comments allowed), so nothing is settable twice, and the admin panel can change a setting without disturbing the rest of
the file. Each component ships a `config.example.json`.

## Building

The target platform is **Debian 13**: that is what these components are built,
tested and deployed on, and the only one their behaviour is stated for.

```
git clone --recurse-submodules https://github.com/bazarish/bazarish-server
cmake -S bazarish-server -B build
cmake --build build -j4
ctest --test-dir build
```

The i2pd patch overlay is applied to the submodule working tree at configure
time, so a fresh clone needs no manual patching.

A single component can also be configured on its own (`cmake -S server-core -B
build-core`); it then picks up the same `common` submodule from one directory up.

## Installing

`packaging/deb/build.sh <out-dir>` builds, tests and packs six Debian 13 packages:

| Package | What it installs |
|---|---|
| `bazarish-setup` | `bazarish-setup`, the user `bazarish`, `/etc/bazarish` and `/var/lib/bazarish` |
| `bazarish-server-core` | message delivery and mailboxes |
| `bazarish-server-service` | accounts, registration and the service portal |
| `bazarish-facade` | the I2P address clients reach the server at |
| `bazarish-admin-panel` | the web panel that runs the services of one server |
| `bazarish-gateway` | the I2P router for clients that run none; it works on its own |

server-core and the server service together are the server: neither starts without
the other, on the same host or on another. Every package but `bazarish-setup` depends on
it.

Every binary here reports the nearest release tag `vX.Y.Z` as `X.Y.Z (<commit>)`, or
`dev (<commit>)` before the first one. A package built on the tag is version `X.Y.Z`;
one built after it is `X.Y.Z+<commits since the tag>.<commit>`, newer than the tag and
older than the next one; before the first tag it is `0~dev.<commits>+<commit>`.

The first install of a service runs `bazarish-setup init <service>`: it writes the
service's config into `/etc/bazarish`, its keys under `/var/lib/bazarish`, links it with
the services already on this host over loopback, and enables its unit. A unit starts
only once `bazarish-setup ready <service>` says its links are all there, so a service
that waits for another host is enabled and stays down until it is linked. At the end
of an install `bazarish-setup waiting` says what each service here still waits for.

An upgrade or a reinstall leaves `/etc/bazarish` and `/var/lib/bazarish` exactly as
they were and restarts only the units that are enabled; a unit the operator disabled
stays disabled. `packaging/deb/upgrade-test.sh` checks this byte by byte over an
installed server, in a throwaway container.

### bazarish-setup

| Command | What it does |
|---|---|
| `init <service>` | writes the service's config and keys, once, and links it with the services here |
| `ready <service>` | exits 0 when the service has every link it needs |
| `waiting` | what each service here still waits for, and the commands that give it |
| `status [--json]` | the services here: their sockets, keys and links |
| `token <service>` | one line with what another host needs of this service |
| `join <token>` | links the services here with the one the token names |
| `listen <service> <address>` | moves the sockets other hosts dial onto an address of this host |
| `gateway-link [<public address>]` | the link clients take for this gateway |

`<service>` is `server-core`, `server-service`, `facade`, `admin-panel` or `gateway`.
A command that changes a service restarts its unit when the unit is enabled.

A token names where a service is reached and the key it presents; a server service's
and a panel's also name their signing key. Pass tokens over a channel you trust: a
forged one points a service at someone else's key. `token` refuses a service that
listens on loopback only: run `listen` first. The sockets `listen` moves are TLS with
the other side's key pinned and every operator call signed; let only the other hosts
of the setup reach them:

| Service | Sockets |
|---|---|
| server-core | `listen`, `opsListen`, `gatewayListen` |
| server-service | `listen`, `opsListen` |
| facade | `opsListen`, `directListen` |
| gateway | `opsListen` |

### Everything on one host

```
apt install ./bazarish-setup_*.deb ./bazarish-server-core_*.deb \
    ./bazarish-server-service_*.deb ./bazarish-facade_*.deb \
    ./bazarish-admin-panel_*.deb ./bazarish-gateway_*.deb
```

The install links every service with every other and prints the two steps left: sign
in to the panel through an SSH tunnel, and give the gateway its public address with
`bazarish-setup gateway-link https://<the front's name>` once a TLS front is before it
(`gateway/README.md`).

### The server: core, service and panel

```
apt install ./bazarish-setup_*.deb ./bazarish-server-core_*.deb \
    ./bazarish-server-service_*.deb ./bazarish-admin-panel_*.deb
```

With the server service on another host, install `bazarish-server-core` and
`bazarish-admin-panel` on one and `bazarish-server-service` on the other, then:

```
core host:     bazarish-setup listen server-core <core address>
               bazarish-setup token server-core
               bazarish-setup token admin-panel
service host:  bazarish-setup join <admin-panel token>
               bazarish-setup listen server-service <service address>
               bazarish-setup token server-service
core host:     bazarish-setup join <server-service token>
service host:  bazarish-setup join <server-core token>
```

The server service asks the running core for its card when it starts, so the core
takes the server service's token first.

### A facade on its own host

```
facade host:   apt install ./bazarish-setup_*.deb ./bazarish-facade_*.deb
server host:   bazarish-setup listen server-core <server address>
               bazarish-setup listen server-service <server address>
               bazarish-setup token server-core
               bazarish-setup token server-service
               bazarish-setup token admin-panel
facade host:   bazarish-setup join <server-core token>
               bazarish-setup join <server-service token>
               bazarish-setup join <admin-panel token>
               bazarish-setup listen facade <facade address>
               bazarish-setup token facade
panel host:    bazarish-setup join <facade token>
```

Saving the panel's settings then writes the facade's address into the server service,
and the address reaches the descriptor users paste.

### A gateway

```
apt install ./bazarish-setup_*.deb ./bazarish-gateway_*.deb
bazarish-setup gateway-link https://<the front's name>
```

The gateway runs on its own: the link is all its users need. To run it from a panel,
install `bazarish-admin-panel` beside it, or join a panel on another host:

```
gateway host:  bazarish-setup join <admin-panel token>
               bazarish-setup listen gateway <gateway address>
               bazarish-setup token gateway
panel host:    bazarish-setup join <gateway token>
```

A panel that also runs a server links the gateway with its server-core when its
settings are saved, so the gateway routes that server's users without I2P. Several facades and gateways are
installed and joined the same way, each on its own host.
