#!/bin/bash
# Bazarish project (c) 2026
# Builds, tests and packs bazarish-server and bazarish-gateway as .deb packages for
# Debian 13: build.sh <version> <out-dir>. Runs from the repository root on a Debian 13
# host with the build dependencies.
set -euo pipefail
umask 022

readonly kVersion=$1
readonly kOut=$2
readonly kJobs=${BAZARISH_JOBS:-4}
readonly kBuild=build-deb
readonly kArch=$(dpkg --print-architecture)

if [[ ! $kVersion =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "the version is three numbers, as in 1.2.3: $kVersion" >&2
    exit 1
fi

cmake -S . -B "$kBuild" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$kBuild" -j"$kJobs"
ctest --test-dir "$kBuild" -j"$kJobs" --output-on-failure

stageOf() {
    echo "$kBuild/stage-$1"
}

# installProgram <package> <built binary>
installProgram() {
    local -r target="$(stageOf "$1")/usr/lib/$1/$(basename "$2")"
    install -D -m 0755 "$kBuild/$2" "$target"
    strip --strip-unneeded "$target"
}

# installUnit <package> <unit>
installUnit() {
    install -D -m 0644 "packaging/$2.service" "$(stageOf "$1")/usr/lib/systemd/system/$2.service"
}

# installTree <package> <source dir> <shared dir>
installTree() {
    local -r target="$(stageOf "$1")/usr/share/$1/$3"
    mkdir -p "$target"
    cp -r "$2/." "$target/"
}

# dpkg-shlibdeps reads the package name from a control file beside the binaries.
libraryDepends() {
    local -r probe=$kBuild/shlibs-$1
    local -r programs="$PWD/$(stageOf "$1")/usr/lib/$1"
    rm -rf "$probe"
    mkdir -p "$probe/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$1" "$1" > "$probe/debian/control"
    (cd "$probe" && dpkg-shlibdeps -O "$programs"/*) | sed -n 's/^shlibs:Depends=//p'
}

# pack <package> <depends> <summary> <description>
pack() {
    local -r stage=$(stageOf "$1")
    local libraries
    libraries=$(libraryDepends "$1")
    mkdir -p "$stage/DEBIAN"
    cat > "$stage/DEBIAN/control" <<CONTROL
Package: $1
Version: $kVersion
Architecture: $kArch
Maintainer: Bazarish <noreply@bazari.sh>
Depends: adduser, systemd, ca-certificates, $2$libraries
Section: net
Priority: optional
Homepage: https://bazari.sh
Description: $3
 $4
CONTROL
    for script in postinst prerm postrm; do
        install -m 0755 "packaging/deb/$1/$script" "$stage/DEBIAN/$script"
    done
    mkdir -p "$kOut"
    dpkg-deb --root-owner-group --build "$stage" "$kOut/${1}_${kVersion}_${kArch}.deb"
}

rm -rf "$(stageOf bazarish-gateway)" "$(stageOf bazarish-server)"

installProgram bazarish-gateway gateway/bazarish-gateway
installUnit bazarish-gateway bazarish-gateway
install -D -m 0644 gateway/README.md \
    "$(stageOf bazarish-gateway)/usr/share/doc/bazarish-gateway/README.md"
pack bazarish-gateway "" "Bazarish gateway" \
    "Runs the I2P router for Bazarish clients that do not run their own."

for program in server-core/bazarish-server service-node/bazarish-service-node \
    facade-http/bazarish-facade-http admin-panel/bazarish-admin-panel setup/bazarish-setup; do
    installProgram bazarish-server "$program"
done
for unit in bazarish-server bazarish-service-node bazarish-facade bazarish-admin-panel; do
    installUnit bazarish-server "$unit"
done
installTree bazarish-server admin-panel/web admin-panel
installTree bazarish-server service-node/portal portal
install -D -m 0644 README.md "$(stageOf bazarish-server)/usr/share/doc/bazarish-server/README.md"
pack bazarish-server "bazarish-gateway (= $kVersion), " "Bazarish server" \
    "Message delivery, accounts, the client-facing facade and the admin panel."
