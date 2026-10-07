#!/bin/sh
# Build the Windows MSI on Linux using wixl from msitools.
#
# Usage: templates/build-msi.sh <version> <output.msi>
#
# <version> may be a git tag or "git describe" output (eg v1.2.3 or
# v1.2.3-4-gabcdef); it is reduced to major.minor.patch for the MSI
# ProductVersion. Run from the repository root after GoReleaser has
# populated dist/.
#
# Requires wixl 0.106 or later, which is the first release to support
# <Condition> inside <Component>.
set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 <version> <output.msi>" >&2
	exit 2
fi

version=$(printf '%s' "$1" | sed -e 's/^v//' -e 's/[-+].*$//')
output=$2

if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "invalid version: $1" >&2
	exit 1
fi

wixl_version=$(wixl --version)
if [ "$(printf '%s\n%s\n' 0.106 "$wixl_version" | sort -V | head -n 1)" != 0.106 ]; then
	echo "wixl $wixl_version found but 0.106 or later is required" >&2
	exit 1
fi

templates=$(dirname "$0")
root=$(cd "$templates/.." && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The licence agreement dialog needs RTF, so escape the RTF control
# characters and end each line with a line break.
if LC_ALL=C grep -q '[^ -~	]' "$root/LICENSE"; then
	echo "LICENSE contains non-ASCII characters which are not handled by the RTF conversion" >&2
	exit 1
fi
{
	printf '{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Courier New;}}\\f0\\fs16\n'
	sed -e 's/\\/\\\\/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/$/\\line/' "$root/LICENSE"
	printf '}\n'
} > "$work/LICENSE.rtf"

wixl --ext ui --arch x64 \
	-D Version="$version" \
	-D DistDir="$root/dist" \
	-D PolicyDir="$root/policy" \
	-D LicenseRtf="$work/LICENSE.rtf" \
	-o "$output" \
	"$templates"/*.wxs
