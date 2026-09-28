# Bazarish server fleet

Every server-side component of Bazarish in one build tree. The protocol they
implement is specified in the `docs-main` repository; the desktop client
(`client-qt6`), the alias service (`alias-resolver`) and the shared library
(`common-cpp`) live in their own repositories.

| Directory | Binary | Role |
|---|---|---|
| `server-core` | `bazarish-server` | message delivery, mailboxes, federation over I2P |
| `service-node` | `bazarish-service-node` | registration, accounts, the browser portal |
| `facade-http` | `bazarish-facade-http` | the client-facing last mile: a sealed tunnel, forwarded blind |
| `admin-panel` | `bazarish-admin-panel` | operator UI, authenticated by identity signature |
| `common` | - | submodule of `common-cpp`: crypto, I2P transport, embedded i2pd |

The components stay separate processes and separate deployment units - a facade
compromise still must not reach the server. Sharing a repository only removes the
per-component submodule bump and the per-component rebuild of the embedded I2P
router.

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
build-core`); it then expects a checkout of the common repository as a sibling
directory.
