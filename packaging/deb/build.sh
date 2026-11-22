#!/bin/bash
# Bazarish project (c) 2026
# Builds, tests and packs the Bazarish server packages for Debian 13: build.sh <out-dir>.
set -euo pipefail
umask 022

readonly kOut=$1
readonly kJobs=${BAZARISH_JOBS:-4}
readonly kBuild=build-deb
readonly kArch=$(dpkg --print-architecture)

# The nearest release tag, past it the commits since and the hash, so that apt takes a later build for newer.
if described=$(git describe --tags --long --match 'v[0-9]*' 2>/dev/null); then
    tag=${described%-*-g*}
    if [[ ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "a release tag is v and three numbers, as in v1.2.3: $tag" >&2
        exit 1
    fi
    since=${described#"$tag"-}
    since=${since%%-*}
    if [ "$since" = 0 ]; then
        readonly kVersion=${tag#v}
    else
        readonly kVersion=${tag#v}+$since.$(git rev-parse --short HEAD)
    fi
else
    readonly kVersion=0~dev.$(git rev-list --count HEAD)+$(git rev-parse --short HEAD)
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
    rm -rf "$probe"
    mkdir -p "$probe/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$1" "$1" > "$probe/debian/control"
    local programs
    mapfile -t programs < <(find "$PWD/$(stageOf "$1")/usr" -type f \
        \( -path '*/usr/bin/*' -o -path '*/usr/lib/bazarish-*' \))
    (cd "$probe" && dpkg-shlibdeps -O "${programs[@]}") | sed -n 's/^shlibs:Depends=//p'
}

# pack <package> <depends> <maintainer scripts dir> <summary> <description>
pack() {
    local -r stage=$(stageOf "$1")
    local libraries
    libraries=$(libraryDepends "$1")
    mkdir -p "$stage/DEBIAN"
    cat > "$stage/DEBIAN/control" <<CONTROL
Package: $1
Version: $kVersion
Architecture: $kArch
Maintainer: Bazarish <gusto@bazari.sh>
Depends: $2$libraries
Section: net
Priority: optional
Homepage: https://bazarish.org
Description: $4
 $5
CONTROL
    local script
    for script in "$3"/*; do
        install -m 0755 "$script" "$stage/DEBIAN/$(basename "$script")"
    done
    if [ -f "$stage/DEBIAN/triggers" ]; then
        chmod 0644 "$stage/DEBIAN/triggers"
    fi
    mkdir -p "$kOut"
    dpkg-deb --root-owner-group --build "$stage" "$kOut/${1}_${kVersion}_${kArch}.deb"
}

# service <package> <kind> <unit> <built binary> <summary> <description>
service() {
    installProgram "$1" "$4"
    installUnit "$1" "$3"
    local -r scripts=$kBuild/scripts-$1
    mkdir -p "$scripts"
    local script
    for script in postinst prerm postrm; do
        sed "s/@KIND@/$2/; s/@UNIT@/$3/" "packaging/deb/service/$script" > "$scripts/$script"
    done
    pack "$1" "bazarish-setup (= $kVersion), systemd, " "$scripts" "$5" "$6"
}

readonly kPackages=(bazarish-setup bazarish-server-core bazarish-server-service bazarish-facade
    bazarish-admin-panel bazarish-gateway)
for package in "${kPackages[@]}"; do
    rm -rf "$(stageOf "$package")" "$kBuild/scripts-$package"
done

install -D -m 0755 "$kBuild/setup/bazarish-setup" "$(stageOf bazarish-setup)/usr/bin/bazarish-setup"
strip --strip-unneeded "$(stageOf bazarish-setup)/usr/bin/bazarish-setup"
install -D -m 0644 README.md "$(stageOf bazarish-setup)/usr/share/doc/bazarish-setup/README.md"
pack bazarish-setup "adduser, ca-certificates, " packaging/deb/bazarish-setup "Bazarish service setup" \
    "Writes the configs and keys of the Bazarish services and links them, here and across hosts."

service bazarish-server-core server-core bazarish-server-core server-core/bazarish-server-core \
    "Bazarish server core" "Message delivery and mailboxes; federation over I2P."
installTree bazarish-server-service server-service/portal portal
service bazarish-server-service server-service bazarish-server-service \
    server-service/bazarish-server-service "Bazarish server service" \
    "Accounts, registration and the service portal of a Bazarish server."
service bazarish-facade facade bazarish-facade facade-http/bazarish-facade-http \
    "Bazarish facade" "The I2P address clients reach a Bazarish server at."
installTree bazarish-admin-panel admin-panel/web web
service bazarish-admin-panel admin-panel bazarish-admin-panel admin-panel/bazarish-admin-panel \
    "Bazarish admin panel" "The web panel that runs the Bazarish services of one server."
install -D -m 0644 gateway/README.md \
    "$(stageOf bazarish-gateway)/usr/share/doc/bazarish-gateway/README.md"
service bazarish-gateway gateway bazarish-gateway gateway/bazarish-gateway \
    "Bazarish gateway" "Runs the I2P router for Bazarish clients that do not run their own."
