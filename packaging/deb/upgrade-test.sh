#!/bin/bash
# Bazarish project (c) 2026
# upgrade-test.sh <out-dir>: installs the packages build.sh left there, changes what an
# operator would, installs them again as the next version and fails if anything under
# /etc/bazarish or /var/lib/bazarish changed. It installs into this system: run it as
# root in a throwaway Debian 13 container only.
set -euo pipefail

readonly kOut=$1
readonly kNotice="To finish:"
readonly kData=(/etc/bazarish /var/lib/bazarish)
readonly kOperatorFile=written-by-the-operator
kWork=$(mktemp -d)
readonly kWork
export DEBIAN_FRONTEND=noninteractive

installPackages() {
    apt-get install -y -qq --reinstall "$@" 2>&1
}

snapshot() {
    find "${kData[@]}" -printf '%M %u %g %p\n' | sort
    find "${kData[@]}" -type f -print0 | sort -z | xargs -0 sha256sum
}

# nextVersion <deb>: the same package under a version apt takes for newer.
nextVersion() {
    local -r unpacked=$kWork/$(basename "$1" .deb)
    dpkg-deb -R "$1" "$unpacked"
    local -r version=$(sed -n 's/^Version: //p' "$unpacked/DEBIAN/control")
    local -r next=$version.1
    sed -i "s/^Version: .*/Version: $next/; s/(= $version)/(= $next)/" "$unpacked/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$unpacked" "$kWork/$(basename "$1" | sed "s/_${version}_/_${next}_/")" >/dev/null
}

readonly kFirst=(./"$kOut"/bazarish-gateway_*.deb ./"$kOut"/bazarish-server_*.deb)
if ! first=$(installPackages "${kFirst[@]}"); then
    echo "$first" >&2
    exit 1
fi
if [ "$(grep -c "$kNotice" <<<"$first")" -ne 2 ]; then
    echo "the first install did not say what is left, both packages should have:" >&2
    echo "$first" >&2
    exit 1
fi
for config in server-core service-node facade admin-panel gateway; do
    if [ ! -s "/etc/bazarish/$config.json" ]; then
        echo "the first install wrote no $config.json" >&2
        exit 1
    fi
done

python3 - <<'OPERATOR'
import json
def change(name, edit):
    path = f"/etc/bazarish/{name}.json"
    with open(path) as file:
        config = json.load(file)
    edit(config)
    with open(path, "w") as file:
        json.dump(config, file)
change("admin-panel", lambda c: c.update(admin=["the-operator-who-claimed-it"]))
change("service-node", lambda c: c.update(registration={"requireApproval": True}))
change("gateway", lambda c: c.update(token="the-token-clients-were-given"))
OPERATOR
for state in /var/lib/bazarish/*/; do
    echo "$state" > "$state$kOperatorFile"
done
snapshot > "$kWork/before"

for deb in "${kFirst[@]}"; do
    nextVersion "$deb"
done
for round in reinstall upgrade; do
    if [ "$round" = reinstall ]; then
        packages=("${kFirst[@]}")
    else
        packages=("$kWork"/*.deb)
    fi
    if ! said=$(installPackages "${packages[@]}"); then
        echo "$said" >&2
        exit 1
    fi
    if grep -q "$kNotice" <<<"$said"; then
        echo "the $round set the server up again:" >&2
        echo "$said" >&2
        exit 1
    fi
    snapshot > "$kWork/after"
    if ! diff -u "$kWork/before" "$kWork/after"; then
        echo "the $round changed the operator's data" >&2
        exit 1
    fi
    echo "$round: every file under ${kData[*]} kept its bytes, owner and mode"
done
dpkg-query -W bazarish-gateway bazarish-server
