#!/bin/bash
#
# refresh-lab-packages - rebuild the open-bastion development packages and
# republish them to the APT repository the fleet installs from.
#
# Usage: scripts/refresh-lab-packages.sh [--skip-build] [--index-only] [--check]
#
#   --skip-build  publish the .deb already built next to the open-bastion
#                 checkout, instead of building a new one
#   --index-only  only regenerate the APT index of the served directory
#   --check       print what would happen, change nothing
#
# Environment:
#   OB_REPO     path to the open-bastion checkout (default: ../open-bastion)
#   OB_LAB_DIR  APT repository served to the fleet (default: /srv/ob-lab)
#   OB_APT_PORT port the local HTTP server listens on (default: 8000)
#
# See "Testing a fix of the deployment" in README.md.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
OB_REPO=${OB_REPO:-"$root/../open-bastion"}
OB_LAB_DIR=${OB_LAB_DIR:-/srv/ob-lab}
OB_APT_PORT=${OB_APT_PORT:-8000}

skip_build=0
index_only=0
check=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) skip_build=1 ;;
        --index-only) index_only=1 ;;
        --check) check=1 ;;
        -h | --help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

[ -d "$OB_LAB_DIR" ] || {
    echo "no APT directory at $OB_LAB_DIR (set OB_LAB_DIR)" >&2
    exit 1
}
command -v dpkg-scanpackages >/dev/null || {
    echo "dpkg-scanpackages is missing (install dpkg-dev)" >&2
    exit 1
}

# dpkg-buildpackage writes its output next to the checkout, not in it, and
# the packages are moved from there into the served directory.
debs_dir=$(dirname "$OB_REPO")
shopt -s nullglob
debs=("$debs_dir"/open-bastion*_0.*.deb)

if [ "$index_only" -eq 0 ] && [ "$skip_build" -eq 0 ]; then
    [ -d "$OB_REPO" ] || {
        echo "no open-bastion checkout at $OB_REPO (set OB_REPO)" >&2
        exit 1
    }
    if [ "$check" -eq 1 ]; then
        echo "==> would build the development packages in $OB_REPO"
    else
        echo "==> Building the development packages in $OB_REPO"
        (cd "$OB_REPO" && ./scripts/build-dev-deb)
        debs=("$debs_dir"/open-bastion*_0.*.deb)
    fi
fi

if [ "$check" -eq 1 ]; then
    if [ "$index_only" -eq 1 ]; then
        echo "==> would regenerate Packages and Packages.gz in $OB_LAB_DIR"
        exit 0
    fi
    printf '==> would publish %d package(s) to %s:\n' "${#debs[@]}" "$OB_LAB_DIR"
    printf '      %s\n' "${debs[@]##*/}"
    echo "==> would regenerate Packages and Packages.gz"
    exit 0
fi

if [ "$index_only" -eq 0 ]; then
    [ "${#debs[@]}" -gt 0 ] || {
        echo "no open-bastion .deb in $debs_dir" >&2
        echo "build one first, or run without arguments to let this script build it" >&2
        exit 1
    }

    echo "==> Publishing ${#debs[@]} package(s) to $OB_LAB_DIR"
    # Replace the previous build rather than pile versions up: the fleet
    # installs whatever the index holds, and an older .deb left in the
    # directory is a version something may still install.
    rm -f "$OB_LAB_DIR"/open-bastion*_0.*.deb
    cp -p "${debs[@]}" "$OB_LAB_DIR/"
fi

echo "==> Regenerating the APT index"
(cd "$OB_LAB_DIR" && dpkg-scanpackages -m . /dev/null >Packages && gzip -kf Packages)

versions=$(for deb in "$OB_LAB_DIR"/open-bastion_0.*_amd64.deb; do
    dpkg-deb -f "$deb" Version
done | sort -u)
echo "==> Served open-bastion: $(printf '%s ' $versions)"
if [ "$(printf '%s\n' $versions | wc -l)" -gt 1 ]; then
    echo "!! Several versions are served; remove the ones you do not want"
fi

if command -v ss >/dev/null && ! ss -ltn | grep -q ":$OB_APT_PORT "; then
    echo "!! Nothing listens on port $OB_APT_PORT; start it with:"
    echo "     python3 -m http.server $OB_APT_PORT --directory $OB_LAB_DIR"
fi
