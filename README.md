# Bazarish server fleet

Every server-side component of Bazarish in one build tree. The protocol they
implement is specified in the `docs-main` repository; the desktop client
(`client-qt`), the alias service (`alias-resolver`) and the shared library
(`common-cpp`) live in their own repositories.

| Directory | Binary | Role |
|---|---|---|
| `server-core` | `bazarish-server` | message delivery, mailboxes, federation over I2P |
| `service-node` | `bazarish-service-node` | registration, accounts, the browser portal |
| `facade-http` | `bazarish-facade-http` | the client-facing last mile: a sealed tunnel, forwarded blind |
| `admin-panel` | `bazarish-admin-panel` | operator UI, authenticated by identity signature |
| `gateway` | `bazarish-gateway` | optional: runs the I2P router for clients that do not run their own |
| `setup` | `bazarish-setup` | the package's first install: every config, linked by the keys it makes |
| `common` | - | submodule of `common-cpp`: crypto, I2P transport, embedded i2pd |

The gateway is the one optional component: nothing else here depends on it, and
it needs nothing from the rest.

The components stay separate processes and separate deployment units - a facade
compromise still must not reach the server. They reach each other over TLS,
pinned by the key each one prints when it starts, so a fleet can be spread over
several machines without a tunnel between them. Sharing a repository only
removes the per-component submodule bump and the per-component rebuild of the
embedded I2P router.

Every component takes exactly one flag: `--config <path>`. Values live in that
file (JSON, comments allowed) rather than in unit files, so nothing is settable
twice, and the admin panel can change a setting without disturbing the rest of
the file. Each component ships a `config.example.json`.

## Building

The target platform is **Debian 13**: that is what these components are built,
tested and deployed on, and the only one their behaviour is stated for. They are
server processes and are not meant to run anywhere else - the desktop client is
the part that goes wherever the user is.

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

`packaging/deb/build.sh <version> <out-dir>` builds, tests and packs two Debian 13
packages:

- `bazarish-gateway` - the gateway alone. It needs nothing else to run.
- `bazarish-server` - server-core, the service node, the facade and the admin
  panel, with `bazarish-gateway` as a dependency.

The first install of `bazarish-server` runs `bazarish-setup`. It writes the four
configs into `/etc/bazarish`, makes every service's keys under `/var/lib/bazarish`
and links the services, the gateway and the panel to each other by those keys,
all on loopback. A gateway that already has operators keeps them, the panel is
added beside them. The install then prints what is left to do.

An upgrade or a reinstall leaves `/etc/bazarish` and `/var/lib/bazarish` exactly as
they were: the packages own neither, and `bazarish-setup` writes nothing once any
of its configs is there. `packaging/deb/upgrade-test.sh` checks this byte by byte
over an installed server, in a throwaway container. CI builds, tests, packs and
upgrade-tests both architectures on every push; a `vX.Y.Z` tag publishes the
packages in a GitHub release.
