#!/bin/sh
# Writes the country address list of a release: veilway-geoip.txt, or the path given as the first argument.
# Source: the five registries' public "delegated-extended" files, over https. Kept: ipv4 and ipv6 lines with the status allocated or assigned and a two letter country.
# Format (read by crates/veilway-core/src/config/geoip.rs): a header `veilway-geoip 1 <YYYY-MM-DD>`, then sorted lines `<cc> 4 <first address> <count>` and `<cc> 6 <network> <prefix length>`.
# It fails, and writes nothing, when a download fails or is empty or the result is too small to be the real data.
set -eu
out="${1:-veilway-geoip.txt}"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
for url in https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest; do
	curl -fsSL --proto "=https" --retry 8 --retry-all-errors -C - --connect-timeout 30 --speed-limit 10000 --speed-time 60 -o "$dir/$(basename "$url")" "$url"
	[ -s "$dir/$(basename "$url")" ] || { echo "geoip.sh: $url is empty" >&2; exit 1; }
done
cat "$dir"/delegated-* | awk -F"|" '($3 == "ipv4" || $3 == "ipv6") && ($7 == "allocated" || $7 == "assigned") && $2 ~ /^[A-Z][A-Z]$/ && $5 ~ /^[0-9]+$/ {print tolower($2), substr($3, 4), $4, $5}' | LC_ALL=C sort -u > "$dir/body"
lines="$(wc -l < "$dir/body")"
countries="$(cut -d " " -f 1 "$dir/body" | sort -u | wc -l)"
[ "$lines" -ge 100000 ] && [ "$countries" -ge 200 ] || { echo "geoip.sh: $lines lines and $countries countries is too little" >&2; exit 1; }
{ echo "veilway-geoip 1 $(date -u +%Y-%m-%d)"; cat "$dir/body"; } > "$out"
echo "geoip.sh: wrote $out with $lines lines for $countries countries"
