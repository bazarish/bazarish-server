#!/bin/bash
# Bazarish project (c) 2026
# Installs into this system: run as root in a throwaway Debian 13 container only.
set -euo pipefail

readonly kOut=$1
readonly kPanelNotice="administers the panel"
readonly kGatewayNotice="bazarish-setup gateway-link"
readonly kWaiting="starts once it is linked"
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

readonly kFirst=(./"$kOut"/bazarish-*.deb)
readonly kKinds=(server-core server-service facade admin-panel gateway)
if ! first=$(installPackages "${kFirst[@]}"); then
    echo "$first" >&2
    exit 1
fi
for notice in "$kPanelNotice" "$kGatewayNotice"; do
    if [ "$(grep -c "$notice" <<<"$first")" -ne 1 ]; then
        echo "the first install did not say once: $notice" >&2
        echo "$first" >&2
        exit 1
    fi
done
if grep -q "$kWaiting" <<<"$first"; then
    echo "the first install left a service waiting:" >&2
    echo "$first" >&2
    exit 1
fi
for kind in "${kKinds[@]}"; do
    if [ ! -s "/etc/bazarish/$kind.json" ]; then
        echo "the first install wrote no $kind.json" >&2
        exit 1
    fi
    if ! bazarish-setup ready "$kind"; then
        echo "the $kind is not linked after the first install" >&2
        exit 1
    fi
    if [ "$(stat -c %U "/etc/bazarish/$kind.json")" != bazarish ]; then
        echo "$kind.json does not belong to the service user" >&2
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
change("server-service", lambda c: c.update(registration={"requireApproval": True}))
change("gateway", lambda c: c.update(basePath="/the-path-clients-were-given"))
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
    if grep -q -e "$kPanelNotice" -e "$kGatewayNotice" -e "$kWaiting" <<<"$said"; then
        echo "the $round set the services up again:" >&2
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
dpkg-query -W "bazarish-*"
