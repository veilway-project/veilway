#!/bin/sh
# Writes the country address list of a release: veilway-geoip.txt, or the path given as the first argument.
# Source: the five registries' public "delegated-extended" files, over https. Kept: ipv4 and ipv6 lines with the status allocated or assigned and a two letter country.
# Format (read by crates/veilway-core/src/config/geoip.rs): a header `veilway-geoip 1 <YYYY-MM-DD>`, then sorted lines `<cc> 4 <first address> <count>` and `<cc> 6 <network> <prefix length>`.
# It fails, and writes nothing, when a download fails or is empty or the result is too small to be the real data.
set -eu
out="${1:-veilway-geoip.txt}"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
# Each file is downloaded whole each time (no resume: a "latest" file can change between two partial downloads and a resumed one would splice two versions) and checked against the .md5 the registry publishes next to it, when it publishes one. Their formats differ, so only the first 32 hex digits found in it are used.
fetch() {
	name="$(basename "$1")"
	curl -fsSL --proto "=https" --retry 8 --retry-all-errors --connect-timeout 30 --speed-limit 10000 --speed-time 60 -o "$dir/$name" "$1"
	[ -s "$dir/$name" ] || { echo "geoip.sh: $1 is empty" >&2; return 1; }
	curl -fsSL --proto "=https" --retry 3 --retry-all-errors --connect-timeout 30 -o "$dir/$name.md5" "$1.md5" 2>/dev/null || { echo "geoip.sh: $name has no published md5, not checked" >&2; return 0; }
	want="$(grep -Eio '[0-9a-f]{32}' "$dir/$name.md5" | head -n 1 | tr 'A-F' 'a-f')"
	[ -n "$want" ] || { echo "geoip.sh: the md5 of $name has no hash in it, not checked" >&2; return 0; }
	have="$(md5sum "$dir/$name" | cut -d " " -f 1)"
	[ "$want" = "$have" ] || { echo "geoip.sh: $name does not match its published md5" >&2; return 1; }
}
for url in https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest; do
	# A registry that publishes a new file between the two downloads fails the check once, and the next try matches.
	fetch "$url" || fetch "$url" || fetch "$url" || exit 1
done
cat "$dir"/delegated-*-latest | awk -F"|" '($3 == "ipv4" || $3 == "ipv6") && ($7 == "allocated" || $7 == "assigned") && $2 ~ /^[A-Z][A-Z]$/ && $5 ~ /^[0-9]+$/ {print tolower($2), substr($3, 4), $4, $5}' | LC_ALL=C sort -u > "$dir/body"
lines="$(wc -l < "$dir/body")"
countries="$(cut -d " " -f 1 "$dir/body" | sort -u | wc -l)"
[ "$lines" -ge 100000 ] && [ "$countries" -ge 200 ] || { echo "geoip.sh: $lines lines and $countries countries is too little" >&2; exit 1; }
{ echo "veilway-geoip 1 $(date -u +%Y-%m-%d)"; cat "$dir/body"; } > "$out"
echo "geoip.sh: wrote $out with $lines lines for $countries countries"
