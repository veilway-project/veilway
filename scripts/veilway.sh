#!/usr/bin/env bash
# Veilway installer and manager for Linux servers (systemd; x86_64 and aarch64).
#
#   curl -fsSL https://raw.githubusercontent.com/veilway-project/veilway/main/scripts/veilway.sh | sudo bash
#   sudo bash veilway.sh                      interactive menu
#   sudo bash veilway.sh install node|panel|both|mirror [--version vX.Y.Z]
#   sudo bash veilway.sh install panel|both --domain panel.example.com [--web caddy|nginx] [--https-port 443]   also set up a web server with HTTPS and a decoy site
#   sudo bash veilway.sh install panel|both --no-domain [--ip <address>] [--web caddy|nginx] [--https-port 443]   no domain: the subscriptions on this server's IP, self-signed and pinned
#   sudo bash veilway.sh install relay <node-ip> [--transport tls:443 ...] [--rate 50] [--conns 256]   forward ports to a node
#   sudo bash veilway.sh update [node|panel|mirror|both]   also adds the decoy origin (127.0.0.1:8080) and the routes folder of the panel to a web server setup that lacks them
#   bash veilway.sh status | logs [node|panel|mirror] | restart [node|panel|mirror|both]
#   sudo bash veilway.sh check | doctor
#   sudo bash veilway.sh backup [file] | restore <file> | uninstall | version
#   sudo bash veilway.sh addon xray [install|remove|status]
#   sudo bash veilway.sh uninstall relay   remove what install relay added
#   sudo bash veilway.sh uninstall web   remove the web server setup that --domain added
#   sudo bash veilway.sh panel-prefix [/new-path]   move the admin pages to a new path, random when none is given
#   sudo bash veilway.sh admin [list | reset <username>]   show the panel's admins, or give one a new password
#   bash veilway.sh mirror-sync <folder> [--version vX.Y.Z]   copy a release and its signatures into <folder> in GitHub's layout, to serve or carry
#   Flags: --dry-run (print what would happen, change nothing), --yes (no questions), --version <tag>,
#          --allow-downgrade (install a --version older than the installed one),
#          --mirror <url> (repeatable, https only; tried in order, then GitHub), --mirror-only (never fall back to GitHub),
#          --domain <name>, --web caddy|nginx and --https-port <port> (install panel and both; default 443, else the panel is at https://name:port/<prefix>/)
#          --no-domain and --ip <address> (this server's IPv4, found by itself when not given) instead of --domain
#          --no-two-step (fresh install of the panel: password only, no authenticator code; not recommended)
#
# Every download is checked with minisign against the public key below, and the signature's trusted
# comment must read "veilway <tag> <asset>" for the node and "veilway-panel <tag> <asset>" for the panel.
# Nothing is installed without that check, whichever mirror or GitHub the file came from.
# Without --version the newest tag comes from the signed pointer latest-veilway.txt (latest-veilway-panel.txt for the panel),
# whose trusted comment must read "<product> latest <tag>"; a pointer older than what is installed is refused.
# GitHub's own "latest release" answer is the fallback only when no source has a pointer yet.
# A mirror's layout is GitHub's: <mirror>/<owner>/<repo>/releases/download/<tag>/<asset>.
# Environment: NO_COLOR, VEILWAY_PANEL_PORT (default 8480), VEILWAY_DECOY_PORT (default 8080, where the plain site is also served on 127.0.0.1), VEILWAY_MIRRORS (mirror urls separated by spaces, after any --mirror).
# For testing only, to run against a release server of your own (scripts/gate-alpha.sh does): VEILWAY_RELEASE_BASE
# (default https://github.com, still https only), VEILWAY_RAW_BASE (default https://raw.githubusercontent.com),
# VEILWAY_NODE_PUBKEY and VEILWAY_PANEL_PUBKEY (default: the key below), VEILWAY_CADDY_TLS=internal (Caddy's own CA
# instead of Let's Encrypt) and VEILWAY_NGINX_CERT=<cert.pem>:<key.pem> (that certificate instead of certbot). They change
# where a download comes from, which key is trusted and where a certificate comes from. The checks themselves are the same.
# Each one is printed and needs a yes; with --yes, VEILWAY_TESTING=1 too.
set -euo pipefail
umask 022

# The release this script belongs to. The release build writes its tag here, and a version bump sets it on main.
SCRIPT_VERSION="v0.3.11-alpha"
CORE_REPO="veilway-project/veilway"
PANEL_REPO="veilway-project/veilway-panel"
PUBKEY="RWQiodKlFCiJ3bkZD3ojKV7AYyTYf3F5x/XY8upWvpSFTVm3O2cNRbrV"
NODE_PUBKEY="${VEILWAY_NODE_PUBKEY:-$PUBKEY}"
PANEL_PUBKEY="${VEILWAY_PANEL_PUBKEY:-$PUBKEY}"
RELEASE_BASE="${VEILWAY_RELEASE_BASE:-https://github.com}"
RAW_BASE="${VEILWAY_RAW_BASE:-https://raw.githubusercontent.com}"
PANEL_PORT="${VEILWAY_PANEL_PORT:-8480}"
TAG_RE='^v?[0-9A-Za-z._-]+$'
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z.-]+)?$'
IPV4_RE='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
PRIVATE_RE='^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'
NUM_RE='^[1-9][0-9]{0,5}$'
MIRROR_RE='^(https://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)|http://(127(\.[0-9]{1,3}){3}|localhost|\[::1\]))(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'
DOMAIN_RE='^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
OVERRIDES=()
for v in VEILWAY_RELEASE_BASE VEILWAY_RAW_BASE VEILWAY_NODE_PUBKEY VEILWAY_PANEL_PUBKEY VEILWAY_CADDY_TLS VEILWAY_NGINX_CERT; do if [ -n "${!v:-}" ]; then OVERRIDES+=("$v=${!v}"); fi; done
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/veilway"
NODE_DIR="$CONF_DIR/node"
STATE_DIR="/var/lib/veilway"
MIRROR_DIR="/etc/veilway-mirror"
ADDON_DIR="/usr/local/lib/veilway/addons"
GEOIP_FILE="/usr/local/lib/veilway/geoip.txt"
XRAY_RELEASE="v26.10.21"
# Only where the package manager has no minisign. The hash was pinned after the tarball's signature was checked with the author's key RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3.
MINISIGN_VERSION="0.11"
MINISIGN_URL="https://github.com/jedisct1/minisign/releases/download/$MINISIGN_VERSION/minisign-$MINISIGN_VERSION-linux.tar.gz"
MINISIGN_SHA256="f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0"
PANEL_DIR="/var/lib/veilway-panel"
UPDATE_DIR="/var/lib/veilway-panel-update"
SELF="/usr/local/sbin/veilway.sh"
VER_DIR="/var/lib/veilway-installer"
NFT_CONF="/etc/nftables.conf"
NFT_RELAY="/etc/nftables.d/veilway-relay.nft"
SYSCTL_RELAY="/etc/sysctl.d/99-veilway-relay.conf"
RELAY_STATE="$VER_DIR/relay.state"
BACKUP_DIR="/var/backups/veilway"
UNIT_DIR="/etc/systemd/system"
WEB_ROOT="/var/www/veilway-site"
WEB_STATE="$VER_DIR/web.state"
SUB_TLS="/etc/veilway-sub-tls"
SUB_CERT="$SUB_TLS/endpoint.crt"
SUB_KEY="$SUB_TLS/endpoint.key"
DECOY_PORT="${VEILWAY_DECOY_PORT:-8080}"
case "$DECOY_PORT" in ""|*[!0-9]*) DECOY_PORT=8080 ;; esac
DECOY_ON=0
CADDY_SITE="/etc/caddy/conf.d/veilway-panel.caddy"
CADDY_IMPORT="import /etc/caddy/conf.d/*.caddy"
NGINX_SITE="/etc/nginx/conf.d/veilway-panel.conf"
CADDY_DECOY="/etc/caddy/conf.d/veilway-decoy.caddy"
NGINX_DECOY="/etc/nginx/conf.d/veilway-decoy.conf"
CADDY_ROUTES="/etc/caddy/veilway-routes"
NGINX_ROUTES="/etc/nginx/veilway-routes"
DRY=0
ASSUME_YES=0
ALLOW_DOWNGRADE=0
MIRROR_ONLY=0
WANT_VERSION=""
DOMAIN=""
WEB=""
HTTPS_PORT=""
HTTPS_HOST=""
NO_DOMAIN=0
TWO_STEP=on
PUBLIC_IP=""
NODE_HTTPS=0
TAG_OUT=""
TMP=""
MENU=0
MENU_RC=0
CLS=""
WEB_NOW=0
STTY_SAVED=""
MIRRORS=()
SOURCES=()
declare -A DEAD=()

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
	B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; Z=$'\033[0m'
else
	B=""; D=""; R=""; G=""; Y=""; C=""; Z=""
fi
if [ -t 1 ] && grep -qi 'utf-\?8' <<<"${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"; then
	OK="✓"; BAD="✗"; DOT="·"; SPIN='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; H="─"; V="│"; TL="┌"; TR="┐"; BL="└"; BR="┘"; PTR="❯"; LED="●"; UD="↑↓"
else
	OK="+"; BAD="x"; DOT="-"; SPIN="|/-\\"; H="-"; V="|"; TL="+"; TR="+"; BL="+"; BR="+"; PTR=">"; LED="*"; UD="up/down"
fi

# Puts the terminal back after a picker, also from the traps: the cursor is shown and the line settings return.
tty_restore() {
	[ -n "$STTY_SAVED" ] || return 0
	stty "$STTY_SAVED" </dev/tty 2>/dev/null || true
	printf '\033[?25h'
	STTY_SAVED=""
}

cleanup() { tty_restore; [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT
trap 'printf "\n"; exit 130' INT TERM

step() { printf '  %s%s%s %s\n' "$G" "$OK" "$Z" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$Z" "$*"; }
info() { printf '  %s%s%s %s\n' "$D" "$DOT" "$Z" "$*"; }
die() { printf '  %s%s%s %s\n' "$R" "$BAD" "$Z" "$*" >&2; exit 1; }
dry() { printf '  %swould%s %s\n' "$C" "$Z" "$*"; }
rule() { local n="$1" s="" i; for ((i = 0; i < n; i++)); do s+="$H"; done; printf '%s' "$s"; }

header() {
	printf '\n  %sVeilway%s %s%s%s\n  %s%s%s\n\n' "$B" "$Z" "$D" "installer $SCRIPT_VERSION" "$Z" "$D" "$(rule 40)" "$Z"
}

box() {
	local title="$1" w=62 line pad
	shift
	for line in "$@"; do [ "${#line}" -gt "$w" ] && w=${#line}; done
	printf '  %s%s %s%s%s %s%s\n' "$D" "$TL" "$Z$B" "$title" "$Z$D" "$(rule $((w - ${#title})))" "$TR$Z"
	for line in "$@"; do
		pad=$((w - ${#line}))
		[ "$pad" -lt 0 ] && pad=0
		printf '  %s%s%s %s%*s %s%s%s\n' "$D" "$V" "$Z" "$line" "$pad" "" "$D" "$V" "$Z"
	done
	printf '  %s%s%s%s%s\n' "$D" "$BL" "$(rule $((w + 2)))" "$BR" "$Z"
}

row() { printf '  %-14s %s\n' "$1" "$2"; }

# Questions are read from the terminal because stdin is the script itself under curl | bash.
ask() {
	local prompt="$1" default="${2:-}" reply=""
	if [ "$ASSUME_YES" = 1 ] || [ "$DRY" = 1 ]; then printf '%s' "$default"; return 0; fi
	if [ -r /dev/tty ]; then read -r -p "  $prompt " reply </dev/tty || true; else die "no terminal to ask on, pass --yes"; fi
	printf '%s' "${reply:-$default}"
}

confirm() {
	[ "$ASSUME_YES" = 1 ] && return 0
	[ "$DRY" = 1 ] && { dry "ask: $1"; return 0; }
	[ "$(ask "$1 [y/N]" n | tr '[:upper:]' '[:lower:]')" = y ]
}

# In the menu a destructive step asks for its word to be typed. Everywhere else it is the plain question.
confirm_typed() {
	local word="$1"
	shift
	if [ "$MENU" = 1 ] && [ "$ASSUME_YES" = 0 ] && [ "$DRY" = 0 ]; then [ "$(ask "$* Type $word to go on:" "")" = "$word" ]; else confirm "$*"; fi
}

# The list every menu uses. Items are "value|label" and "=Heading" starts a group. The answer is in PICKED, and the return is 1 on q or Esc. <top> is the number of lines already on the screen above the list. Without a usable terminal (no tty, TERM=dumb, under 40 columns) it is a numbered list and a typed number.
pick() {
	local top="$1" quit="$2" i n=0 cur=0 start=0 key rest cand rc num="" rows=0 cols=0 view total cl first drawn=0 mark hint tty=0 text lines=() val=() at=() idx=()
	shift 2
	for i in "$@"; do
		if [ "${i:0:1}" = "=" ]; then lines+=("${i:1}"); idx+=(-1); else val+=("${i%%|*}"); at+=("${#lines[@]}"); lines+=("${i#*|}"); idx+=("$n"); n=$((n + 1)); fi
	done
	total=${#lines[@]}
	if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ] && { : </dev/tty; } 2>/dev/null; then read -r rows cols < <(stty size </dev/tty 2>/dev/null) || true; fi
	[ "${rows:-0}" -ge 10 ] && [ "${cols:-0}" -ge 40 ] && tty=1
	if [ "$tty" = 0 ]; then
		for ((i = 0; i < total; i++)); do
			if [ "${idx[i]}" = -1 ]; then printf '\n  %s%s%s\n' "$D" "${lines[i]}" "$Z"; else printf '  %s%2d%s  %s\n' "$B" $((idx[i] + 1)) "$Z" "${lines[i]}"; fi
		done
		while true; do
			key="$(ask "Number, or q to $quit:" "")"
			case "$key" in
				"" | q | Q) return 1 ;;
				*[!0-9]* | 0*) warn "pick a number from the list" ;;
				*) if [ "$key" -le "$n" ]; then PICKED="${val[key - 1]}"; return 0; fi; warn "pick a number from the list" ;;
			esac
		done
	fi
	view=$((rows - top - 3))
	[ "$view" -ge 5 ] || view=5
	[ "$view" -le "$total" ] || view=$total
	STTY_SAVED="$(stty -g </dev/tty)"
	stty -echo -icanon </dev/tty
	printf '\033[?25l'
	while true; do
		cl=${at[cur]}; first=$cl
		[ "$cl" -gt 0 ] && [ "${idx[cl - 1]}" = -1 ] && first=$((cl - 1))
		[ "$first" -ge "$start" ] || start=$first
		[ "$cl" -lt $((start + view)) ] || start=$((cl - view + 1))
		[ "$drawn" = 0 ] || printf '\033[%dA' $((view + 2))
		for ((i = start; i < start + view; i++)); do
			text="${lines[i]:0:cols - 12}"
			if [ "${idx[i]}" = -1 ]; then printf '\r\033[K  %s%s%s\n' "$D" "$text" "$Z"
			elif [ "${idx[i]}" = "$cur" ]; then printf '\r\033[K  %s%s%s %s%2d  %s%s\n' "$C" "$PTR" "$Z" "$B" $((idx[i] + 1)) "$text" "$Z"
			else printf '\r\033[K    %2d  %s\n' $((idx[i] + 1)) "$text"; fi
		done
		mark=""; [ "$view" = "$total" ] || mark=" $DOT $((cur + 1))/$n"
		hint="$UD move $DOT Enter choose $DOT number jumps $DOT q $quit$mark"
		printf '\r\033[K\n\r\033[K  %s%s%s\n' "$D" "${hint:0:cols - 3}" "$Z"
		drawn=1
		rc=0
		if [ -n "$num" ]; then IFS= read -rsn1 -t 1 key </dev/tty || rc=$?; else IFS= read -rsn1 key </dev/tty || rc=$?; fi
		if [ "$rc" -gt 128 ]; then num=""; continue; fi
		[ "$rc" = 0 ] || key=q
		if [ "$key" = $'\033' ]; then
			rest=""
			IFS= read -rsn2 -t 0.05 rest </dev/tty || true
			case "$rest" in
				"[A" | OA) key=k ;;
				"[B" | OB) key=j ;;
				"") key=q ;;
				*) IFS= read -rsn8 -t 0.02 rest </dev/tty || true; key=x ;;
			esac
		fi
		case "$key" in
			k) cur=$(((cur + n - 1) % n)); num="" ;;
			j) cur=$(((cur + 1) % n)); num="" ;;
			[0-9])
				cand="$num$key"
				if [[ "$cand" =~ ^[1-9][0-9]*$ ]] && [ "$cand" -le "$n" ]; then num="$cand"
				elif [[ "$key" =~ ^[1-9]$ ]] && [ "$key" -le "$n" ]; then num="$key"
				else num=""; fi
				[ -z "$num" ] || cur=$((num - 1))
				;;
			"") PICKED="${val[cur]}"; break ;;
			q | Q) printf '\033[%dA\033[J' $((view + 2)); tty_restore; return 1 ;;
			*) num="" ;;
		esac
	done
	printf '\033[%dA\033[J' $((view + 2))
	tty_restore
}

# Header of a step of the install questions.
wiz() { printf '\n  %sStep %s of 4%s  %s\n\n' "$B" "$1" "$Z" "$2"; }

# Runs a command, or prints it in a dry run.
act() {
	if [ "$DRY" = 1 ]; then dry "$*"; else "$@"; fi
}

need_root() {
	[ "$DRY" = 1 ] && return 0
	[ "$(id -u)" = 0 ] || die "this needs root: run it with sudo"
}

has() { command -v "$1" >/dev/null 2>&1; }

has_systemd() { [ -d /run/systemd/system ]; }

detect_target() {
	case "$(uname -m)" in
		x86_64 | amd64) TARGET="x86_64-unknown-linux-musl" ;;
		aarch64 | arm64) TARGET="aarch64-unknown-linux-musl" ;;
		*) die "unsupported CPU $(uname -m): only x86_64 and aarch64 are built" ;;
	esac
	[ "$(uname -s)" = Linux ] || die "this script is for Linux servers"
}

# A fresh server often runs its automatic updates for the first minutes: apt waits up to 10 minutes for their lock instead of failing, and needrestart does not scan every process after each install.
export NEEDRESTART_SUSPEND=1
pkg_install() {
	if has apt-get; then [ "$DRY" = 1 ] || apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null 2>&1 || true; act env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq "$@"
	elif has dnf; then act dnf install -y -q "$@"
	elif has yum; then act yum install -y -q "$@"
	elif has apk; then act apk add --no-cache -q "$@"
	else return 1; fi
}

ensure_tools() {
	if ! has curl; then
		need_root
		info "installing curl"
		pkg_install curl || die "install curl with your package manager and run this again"
	fi
	if ! has minisign; then
		need_root
		info "installing minisign, which checks every download"
		if ! pkg_install minisign; then
			info "minisign is not in your package manager: installing the author's release $MINISIGN_VERSION to $BIN_DIR, checked against its pinned SHA-256"
			if [ "$DRY" = 1 ]; then dry "download $MINISIGN_URL, check SHA-256 ${MINISIGN_SHA256:0:12}..., install minisign-linux/$(uname -m)/minisign to $BIN_DIR/minisign"
			else
				local tmp; tmp="$(mktemp -d)"
				curl -fsSL --proto "=https" --max-time 120 -o "$tmp/minisign.tar.gz" "$MINISIGN_URL" || { rm -rf "$tmp"; die "cannot download minisign from $MINISIGN_URL. Install it (https://jedisct1.github.io/minisign/) and run this again. Downloads are never installed unchecked."; }
				[ "$(sha256sum "$tmp/minisign.tar.gz" | cut -d " " -f 1)" = "$MINISIGN_SHA256" ] || { rm -rf "$tmp"; die "the minisign download does not match its pinned SHA-256, so nothing was installed"; }
				tar -xzf "$tmp/minisign.tar.gz" -C "$tmp" && install -m 755 "$tmp/minisign-linux/$(uname -m | sed "s/^arm64$/aarch64/;s/^amd64$/x86_64/")/minisign" "$BIN_DIR/minisign" || { rm -rf "$tmp"; die "cannot install minisign to $BIN_DIR"; }
				rm -rf "$tmp"
			fi
		fi
		[ "$DRY" = 1 ] || has minisign || die "minisign did not install"
	fi
	[ "${1:-}" = download ] || has setpriv || die "setpriv (util-linux) is needed to write the node's files as the node user"
}

spin() {
	local pid="$1" msg="$2" i=0
	if [ ! -t 1 ]; then info "$msg"; wait "$pid"; return; fi
	while kill -0 "$pid" 2>/dev/null; do
		printf '\r  %s%s%s %s' "$C" "${SPIN:i++%${#SPIN}:1}" "$Z" "$msg"
		sleep 0.1
	done
	printf '\r\033[K'
	wait "$pid"
}

# Returns curl's status instead of stopping. $4 is the protocols allowed for the first request; redirects are always https.
get_url() {
	local url="$1" out="$2" msg="$3" proto="${4:-=https}" rc=0
	curl -fsSL --proto "$proto" --proto-redir '=https' --tlsv1.2 --retry 3 --connect-timeout 15 -o "$out" "$url" &
	spin $! "$msg" || rc=$?
	return "$rc"
}

fetch() { get_url "$1" "$2" "$3" || die "download failed: $1"; }

# One file from one source (a mirror or $RELEASE_BASE), laid out as GitHub does. Only a loopback mirror may use http. A source that cannot be reached at all is not asked again in this run, so a blocked address costs one wait.
get_from() {
	local base="$1" rel="$2" out="$3" msg="$4" proto="=https" rc=0
	[ -z "${DEAD[$base]:-}" ] || return 1
	if [[ "$base" == http://* && "$base" != "$RELEASE_BASE" ]]; then proto="=http,https"; fi
	get_url "$base/$rel" "$out" "$msg" "$proto" 2>/dev/null || rc=$?
	case "$rc" in 6 | 7 | 28 | 35 | 52 | 56 | 60) DEAD[$base]=1; warn "cannot reach $base: not asking it again in this run" ;; esac
	return "$rc"
}

latest_tag() {
	local repo="$1" url tag
	url="$(curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "$RELEASE_BASE/$repo/releases/latest")" || die "cannot reach GitHub"
	case "$url" in */releases/tag/*) tag="${url##*/}" ;; *) die "$repo has no published release yet" ;; esac
	[[ "$tag" =~ $TAG_RE ]] || die "the latest tag of $repo, \"$tag\", is not a release tag: refusing"
	printf '%s' "$tag"
}

# The version the node or the panel was installed at. Files of the old layout are read until the new one exists.
installed_version() {
	local legacy="$STATE_DIR/node.version" f v=""
	[ "$1" = panel ] && legacy="$PANEL_DIR/panel.version"
	for f in "$VER_DIR/$1.version" "$legacy"; do
		if [ -f "$f" ] && [ ! -L "$f" ]; then v="$(cat "$f")"; break; fi
	done
	if [[ "$v" =~ $TAG_RE ]]; then printf '%s' "$v"; fi
	return 0
}

# A link in these folders may have been planted by the node user, so root stops instead of following it.
refuse_links() {
	local l
	while read -r l; do die "$l is a link: remove it and run this again"; done < <(find "$CONF_DIR" "$STATE_DIR" "$PANEL_DIR" -maxdepth 2 -type l 2>/dev/null)
}

# Writes into the node's folder run as the node user, so root never writes or follows a link there.
as_node_user() { setpriv --reuid veilway --regid veilway --clear-groups "$@"; }

# Downloads one asset with its signature into $TMP from the first source whose file passes: the signature and the trusted comment must both match. A source that gives a bad file is passed over with a warning, and the run stops only when none is left.
download_verified() {
	local repo="$1" key="$2" name="$3" tag="$4" product="$5" base out why comment tried=""
	out="$TMP/$name"
	for base in "${SOURCES[@]}"; do
		tried+="${tried:+, }$base"
		get_from "$base" "$repo/releases/download/$tag/$name" "$out" "downloading $name $tag from $base" || continue
		get_from "$base" "$repo/releases/download/$tag/$name.minisig" "$out.minisig" "downloading signature" || continue
		if ! why="$(minisign -V -m "$out" -x "$out.minisig" -P "$key" 2>&1)"; then warn "signature check failed for $name from $base: $why"; continue; fi
		comment="$(printf '%s\n' "$why" | sed -n 's/^Trusted comment: //p' | head -n 1)"
		if [ "$comment" != "$product $tag $name" ]; then warn "$base gave a signature for \"$comment\", expected \"$product $tag $name\""; continue; fi
		step "signature verified ($name $tag, from $base)"
		return 0
	done
	die "no source gave a verified $name $tag (tried $tried)"
}

# Reads the signed pointer "<product> <tag>" from the first source that has a good one and sets TAG_OUT to the tag, keeping the files in $TMP. Returns 1 when no source has one. Mirrors come first; a pointer that fails its signature or its trusted comment "<product> latest <tag>" is passed over.
pointer_tag() {
	local repo="$1" key="$2" product="$3" base f why line tag
	f="$TMP/latest-$product.txt"
	for base in "${SOURCES[@]}"; do
		get_from "$base" "$repo/releases/latest/download/latest-$product.txt" "$f" "reading the latest pointer from $base" || continue
		get_from "$base" "$repo/releases/latest/download/latest-$product.txt.minisig" "$f.minisig" "reading the pointer's signature" || { warn "$base has a pointer without a signature: passed over"; continue; }
		line="$(head -c 256 "$f")"
		tag="${line#"$product "}"
		if [ "$tag" = "$line" ] || [[ ! "$tag" =~ $TAG_RE ]] || [ "$(wc -l <"$f")" -gt 1 ]; then warn "the pointer from $base does not read \"$product <tag>\": passed over"; continue; fi
		if ! why="$(minisign -V -m "$f" -x "$f.minisig" -P "$key" 2>&1)"; then warn "the pointer from $base fails its signature: $why"; continue; fi
		if [ "$(printf '%s\n' "$why" | sed -n 's/^Trusted comment: //p' | head -n 1)" != "$product latest $tag" ]; then warn "the pointer from $base is signed for another tag or product: passed over"; continue; fi
		TAG_OUT="$tag"
		info "latest is $tag (pointer from $base)"
		return 0
	done
	return 1
}

# Sets TAG_OUT to the tag to install: --version, else the signed pointer, else GitHub's latest release when no source has a pointer yet.
release_tag() {
	local repo="$1" key="$2" product="$3"
	if [ -n "$WANT_VERSION" ]; then TAG_OUT="$WANT_VERSION"; return 0; fi
	pointer_tag "$repo" "$key" "$product" && return 0
	[ "$MIRROR_ONLY" = 0 ] || die "no mirror has a signed latest pointer for $product: pass --version <tag>"
	info "no signed pointer yet, asking GitHub for the latest release"
	TAG_OUT="$(latest_tag "$repo")"
}

install_binary() {
	local src="$1" dest="$2"
	install -m 0755 "$src" "$dest.new"
	mv -f "$dest.new" "$dest"
}

# True when version $1 is lower than $2 by semver precedence, build metadata ignored. Anything that is not semver stops the run.
semver_lower() {
	local a="${1#v}" b="${2#v}" ca cb pa pb i
	local -a x y
	local LC_ALL=C
	[[ "$a" =~ $SEMVER_RE && "$b" =~ $SEMVER_RE ]] || die "cannot compare $1 with $2 as versions: refusing"
	a="${a%%+*}"; b="${b%%+*}"
	ca="${a%%-*}"; cb="${b%%-*}"
	pa="${a#"$ca"}"; pa="${pa#-}"; pb="${b#"$cb"}"; pb="${pb#-}"
	IFS=. read -r -a x <<<"$ca"; IFS=. read -r -a y <<<"$cb"
	for i in 0 1 2; do
		[ "$((10#${x[i]}))" -eq "$((10#${y[i]}))" ] && continue
		return "$((10#${x[i]} >= 10#${y[i]}))"
	done
	if [ -z "$pa" ]; then return 1; fi
	if [ -z "$pb" ]; then return 0; fi
	IFS=. read -r -a x <<<"$pa"; IFS=. read -r -a y <<<"$pb"
	for ((i = 0; i < ${#x[@]} && i < ${#y[@]}; i++)); do
		if [ "${x[i]}" = "${y[i]}" ]; then continue; fi
		if [[ "${x[i]}" =~ ^[0-9]+$ && "${y[i]}" =~ ^[0-9]+$ ]]; then return "$((10#${x[i]} >= 10#${y[i]}))"; fi
		if [[ "${x[i]}" =~ ^[0-9]+$ ]]; then return 0; fi
		if [[ "${y[i]}" =~ ^[0-9]+$ ]]; then return 1; fi
		if [[ "${x[i]}" < "${y[i]}" ]]; then return 0; fi
		return 1
	done
	if [ "${#x[@]}" -lt "${#y[@]}" ]; then return 0; fi
	return 1
}

fetch_and_install() {
	local which="$1" repo key name dest tag product cur vf
	if [ "$which" = node ]; then repo="$CORE_REPO"; key="$NODE_PUBKEY"; product=veilway; name="veilway-$TARGET"; dest="$BIN_DIR/veilway"
	else repo="$PANEL_REPO"; key="$PANEL_PUBKEY"; product=veilway-panel; name="veilway-panel-$TARGET"; dest="$BIN_DIR/veilway-panel"; fi
	if [ "$DRY" = 1 ]; then
		dry "resolve ${WANT_VERSION:-the latest tag (signed pointer latest-$product.txt, trusted comment \"$product latest <tag>\")} of $repo from: ${SOURCES[*]}"
		dry "download $name and $name.minisig, verify with minisign key ${key:0:12}..., match comment \"$product <tag> $name\""
		dry "install -m 0755 $dest"
		return 0
	fi
	release_tag "$repo" "$key" "$product"
	tag="$TAG_OUT"
	cur="$(installed_version "$which")"
	if [ -n "$cur" ] && [ "$cur" != "$tag" ] && semver_lower "$tag" "$cur"; then
		if [ -z "$WANT_VERSION" ]; then die "the latest tag $tag is older than the installed $cur: refusing, a stale or hostile mirror can say this (to go back on purpose: --version $tag --allow-downgrade)"; fi
		[ "$ALLOW_DOWNGRADE" = 1 ] || die "$tag is older than the installed $cur: refusing a downgrade (add --allow-downgrade to do it on purpose)"
		warn "downgrading $which from $cur to $tag, because --allow-downgrade was given"
	fi
	download_verified "$repo" "$key" "$name" "$tag" "$product"
	install_binary "$TMP/$name" "$dest"
	step "installed $dest ($tag)"
	install -d -m 0755 "$VER_DIR"
	vf="$(mktemp "$VER_DIR/.$which.XXXXXX")"
	printf '%s\n' "$tag" >"$vf"; chmod 0644 "$vf"; mv -f "$vf" "$VER_DIR/$which.version"
}

# The country address list of the release the node was just taken from, checked like the binary. The node runs without it, so a failure only warns. Needs the tag that fetch_and_install left in TAG_OUT.
fetch_geoip() {
	local dir="${GEOIP_FILE%/*}"
	if [ "$DRY" = 1 ]; then dry "download veilway-geoip.txt and its .minisig, verify with minisign key ${NODE_PUBKEY:0:12}..., match comment \"veilway <tag> veilway-geoip.txt\", install -m 0644 as $GEOIP_FILE"; return 0; fi
	if ( download_verified "$CORE_REPO" "$NODE_PUBKEY" veilway-geoip.txt "$TAG_OUT" veilway ) && install -d -m 0755 -o root -g root "$dir" && install -m 0644 -o root -g root "$TMP/veilway-geoip.txt" "$GEOIP_FILE.new" && mv -f "$GEOIP_FILE.new" "$GEOIP_FILE"; then step "installed $GEOIP_FILE ($TAG_OUT)"
	else warn "the country address list was not installed: rules that name a country (geoip:tr) will not validate until $GEOIP_FILE exists. Run sudo bash veilway.sh update node to try again"; fi
}

ensure_user() {
	local user="$1" home="$2"
	id "$user" >/dev/null 2>&1 && return 0
	if has useradd; then act useradd --system --home-dir "$home" --no-create-home --shell /usr/sbin/nologin "$user"
	else act adduser -S -D -H -h "$home" -s /sbin/nologin "$user"; fi
	[ "$DRY" = 1 ] || step "created system user $user"
}

backup_file() {
	local f="$1"
	[ -e "$f" ] || return 0
	act mkdir -p "$BACKUP_DIR"
	act cp -p "$f" "$BACKUP_DIR/$(basename "$f").$(date -u +%Y%m%dT%H%M%SZ)"
	step "backed up $f to $BACKUP_DIR"
}

write_unit() {
	local path="$1" content
	content="$(cat)"
	if [ "$DRY" = 1 ]; then dry "write $path"; return 0; fi
	if [ -f "$path" ] && [ "$(cat "$path")" = "$content" ]; then return 0; fi
	backup_file "$path"
	printf '%s\n' "$content" >"$path"
	step "wrote $path"
}

node_unit() {
	write_unit "$UNIT_DIR/veilway.service" <<EOF
[Unit]
Description=Veilway node
Documentation=https://github.com/$CORE_REPO
After=network-online.target
Wants=network-online.target

[Service]
User=veilway
Group=veilway
ExecStart=$BIN_DIR/veilway run --config $NODE_DIR/config.json --state $STATE_DIR/veilway-state.json --replay $STATE_DIR/veilway-replay --api /run/veilway/control.sock
ExecReload=/bin/kill -HUP \$MAINPID
# The control socket is made with mode 600; the panel reaches it through the group veilway.
ExecStartPost=-/usr/bin/timeout 10 /bin/sh -c "until [ -S /run/veilway/control.sock ]; do sleep 0.2; done; chmod 660 /run/veilway/control.sock"
Restart=on-failure
RestartSec=3
RuntimeDirectory=veilway
RuntimeDirectoryMode=0750
LimitNOFILE=65536
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ProtectSystem=strict
# The node writes the config it applied through the control API and the key of a self-signed tls certificate next to it, in its own folder.
ReadWritePaths=$STATE_DIR $NODE_DIR
ProtectHome=true
PrivateTmp=true
PrivateDevices=false
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

# A relay mirror of the subscription endpoint: the node's binary, a user of its own, no capability, and no folder to write. It reads one config file with the secret it shares with the panel, which nobody else can open.
mirror_unit() {
	write_unit "$UNIT_DIR/veilway-mirror.service" <<EOF
[Unit]
Description=Veilway relay mirror
Documentation=https://github.com/$CORE_REPO
After=network-online.target
Wants=network-online.target

[Service]
User=veilway-mirror
Group=veilway-mirror
ExecStart=$BIN_DIR/veilway mirror --config $MIRROR_DIR/mirror.json
Restart=on-failure
RestartSec=3
LimitNOFILE=4096
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

# Xray runs under a user of its own, started by a small host process (`veilway xray-host`) that the node asks over a socket only the node can open. So Xray has no file, key, capability or socket of the node's: its folders are out of its sight, it holds no capability but the one to bind a low port, and it ends with the node.
xray_units() {
	write_unit "$UNIT_DIR/veilway-xray.socket" <<EOF
[Unit]
Description=Veilway Xray host socket
Documentation=https://github.com/$CORE_REPO

[Socket]
ListenStream=/run/veilway-xray/host.sock
SocketUser=veilway
SocketGroup=veilway
SocketMode=0600
DirectoryMode=0755

[Install]
WantedBy=sockets.target
EOF
	write_unit "$UNIT_DIR/veilway-xray.service" <<EOF
[Unit]
Description=Veilway Xray host
Documentation=https://github.com/$CORE_REPO
Requires=veilway-xray.socket
After=veilway-xray.socket

[Service]
User=veilway-xray
Group=veilway-xray
ExecStart=$BIN_DIR/veilway xray-host --addons $ADDON_DIR
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
MemoryMax=1G
TasksMax=4096
# The sockets of the Xray outbounds are made here, by Xray, with mode 660. The folder belongs to this user and its group, which the node's user joins (xray_node_group), and nobody else can enter it.
RuntimeDirectory=veilway-xray-out
RuntimeDirectoryMode=0750
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
# Nothing of the node's is in its sight: not its config with the keys, not its state, not its control socket.
InaccessiblePaths=-$NODE_DIR -$STATE_DIR -$CONF_DIR -$PANEL_DIR -/run/veilway
PrivateTmp=true
PrivateDevices=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
SystemCallArchitectures=native
UMask=0077
EOF
}

# The node is let into the group of Xray's user, and so into the folder of the Xray outbounds' sockets. It is a member of the group in the system's own files, and not a setting of the node's unit, so that `veilway doctor` run as that user sees what the node sees. The node takes the group when it starts.
xray_node_group() {
	getent group veilway-xray >/dev/null 2>&1 || { if has groupadd; then act groupadd --system veilway-xray; else act addgroup -S veilway-xray; fi; }
	if has usermod; then act usermod -aG veilway-xray veilway; else act addgroup veilway veilway-xray; fi
}

panel_unit() {
	write_unit "$UNIT_DIR/veilway-panel.service" <<EOF
[Unit]
Description=Veilway panel
Documentation=https://github.com/$PANEL_REPO
After=network-online.target
Wants=network-online.target

[Service]
User=veilway-panel
Group=veilway-panel
SupplementaryGroups=veilway
ExecStart=$BIN_DIR/veilway-panel run --config $CONF_DIR/panel.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=$PANEL_DIR -$UPDATE_DIR
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

svc() {
	local action="$1" name="$2"
	has_systemd || { warn "systemd is not running here, skipped: systemctl $action $name"; return 0; }
	act systemctl "$action" "$name"
}

daemon_reload() { has_systemd && act systemctl daemon-reload || true; }

# The node's files moved from /etc/veilway into its own folder. They are copied as the node user, then the old copy is removed.
prepare_node_dir() {
	local f
	act install -d -m 0700 -o veilway -g veilway "$NODE_DIR"
	[ "$DRY" = 1 ] && { dry "move $CONF_DIR/config.json and $CONF_DIR/tls-* into $NODE_DIR, where they are"; return 0; }
	for f in "$CONF_DIR/config.json" "$CONF_DIR"/tls-*; do
		[ -f "$f" ] || continue
		if [ -e "$NODE_DIR/${f##*/}" ]; then warn "kept $f: $NODE_DIR/${f##*/} already exists"; continue; fi
		as_node_user cp -n -- "$f" "$NODE_DIR/${f##*/}" || die "cannot copy $f to $NODE_DIR"
		rm -f -- "$f"
		step "moved $f to $NODE_DIR"
	done
}

install_node() {
	local inbound key port p
	step "node"
	ensure_user veilway "$STATE_DIR"
	act install -d -m 0750 -o veilway -g veilway "$STATE_DIR"
	act install -d -m 0750 -o root -g veilway "$CONF_DIR"
	fetch_and_install node
	fetch_geoip
	prepare_node_dir
	node_unit
	install_self
	daemon_reload
	if [ "$DRY" = 1 ]; then
		dry "write $CONF_DIR/config.example.json from the release tag"
		dry "write $NODE_DIR/config.json if there is none: one udp-obfs inbound on a random free UDP port with a new key, and one direct exit"
	else
		tag="$(installed_version node)"
		if [ ! -f "$CONF_DIR/config.example.json" ] && curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "$CONF_DIR/config.example.json" "$RAW_BASE/$CORE_REPO/${tag:-main}/config.example.json" 2>/dev/null; then
			step "wrote $CONF_DIR/config.example.json"
		fi
		# A node needs a config to run, and the panel needs a running node to change it, so a fresh install starts with one working inbound (a veilway inbound with a udp-obfs transport, in the panel's default device pool) and no users. The port is random, never WireGuard's well-known 51820, which a censor may watch. Without a key or a free port it starts with no inbound.
		if [ ! -e "$NODE_DIR/config.json" ]; then
			inbound=""
			key="$("$BIN_DIR/veilway" genkey 2>/dev/null | sed -n 's/^private_key: *//p')"
			port=""
			for p in $((RANDOM % 30000 + 20000)) $((RANDOM % 30000 + 20000)) $((RANDOM % 30000 + 20000)) $((RANDOM % 30000 + 20000)) $((RANDOM % 30000 + 20000)); do
				if ! has ss || [ -z "$(ss -H -lun "sport = :$p" 2>/dev/null)" ]; then port="$p"; break; fi
			done
			if [ -n "$key" ] && [ -n "$port" ]; then inbound="{\"tag\": \"main\", \"type\": \"veilway\", \"private_key\": \"$key\", \"address\": [\"10.66.0.1/16\"], \"transports\": [{\"type\": \"udp-obfs\", \"listen\": \"0.0.0.0:$port\"}]}"; fi
			( umask 077; as_node_user tee "$NODE_DIR/config.json" >/dev/null ) <<EOF
{
	"version": 1,
	"dns": {"servers": ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]},
	"inbounds": [$inbound],
	"users": [],
	"outbounds": [{"tag": "plain", "type": "direct"}],
	"exits": [{"tag": "main", "name": "This server", "backend": {"type": "netstack", "outbound": "plain"}}],
	"routing": {"default": "main", "rules": [
		{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"},
		{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}
	]}
}
EOF
			if [ -n "$inbound" ]; then
				step "wrote $NODE_DIR/config.json: inbound main on UDP port $port (udp-obfs)"
				if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then warn "ufw is active: allow the node's port (sudo ufw allow $port/udp) or devices cannot connect"; fi
			else step "wrote $NODE_DIR/config.json: no inbound yet, add one in the panel"; fi
		fi
		chown -h veilway:veilway "$NODE_DIR/config.json"
		as_node_user chmod 0600 "$NODE_DIR/config.json"
	fi
	if run_check; then svc enable veilway.service; svc restart veilway.service; else warn "config has errors: the node was not restarted"; fi
}

# Written once, never over an existing file. The secret is made here and shown once at the end, for the panel's trusted_mirrors; the upstream is a placeholder the operator replaces, so the unit is enabled and not started until the config names a real panel.
install_mirror() {
	local f="$MIRROR_DIR/mirror.json" secret
	step "mirror"
	ensure_user veilway-mirror "$MIRROR_DIR"
	act install -d -m 0700 -o veilway-mirror -g veilway-mirror "$MIRROR_DIR"
	fetch_and_install node
	mirror_unit
	daemon_reload
	if [ "$DRY" = 1 ]; then dry "write $f from a template with a new secret"; return 0; fi
	if [ -f "$f" ]; then
		info "kept existing $f"
		if as_mirror mirror --check --config "$f"; then svc enable veilway-mirror.service; svc restart veilway-mirror.service; else warn "config has errors: the mirror was not restarted"; fi
		return 0
	fi
	secret="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
	( umask 077; as_mirror_user tee "$f" >/dev/null ) <<EOF
{
	"name": "mirror-1",
	"listen": "127.0.0.1:8490",
	"path": "/sub",
	"upstream": "https://panel.invalid/sub",
	"upstream_pins": [],
	"trusted_proxies": ["127.0.0.1", "::1"],
	"secret": "$secret"
}
EOF
	step "wrote $f"
	svc enable veilway-mirror.service
	box "Relay mirror" \
		"Edit $f: set upstream to your panel's endpoint URL, path to the" \
		"path your web server gives this mirror, and name if you like." \
		"Then: sudo bash veilway.sh restart mirror" \
		"" \
		"On the panel, add this to the \"trusted_mirrors\" of panel.json and restart it:" \
		"  {\"name\": \"mirror-1\", \"secret\": \"$secret\"}" \
		"" \
		"nginx, in front of 127.0.0.1:8490 (599 hands unknown requests back to nginx):" \
		"  location = /sub {" \
		"    proxy_pass http://127.0.0.1:8490;" \
		"    proxy_http_version 1.1;" \
		"    proxy_intercept_errors on;" \
		"    error_page 599 = @unknown;" \
		"    proxy_set_header X-Forwarded-For \$remote_addr; }"
}

# Saves the installer as $SELF for later runs. The root update service runs this copy, so what it runs is not a file the panel's user can reach. A piped run has no file of its own, so the signed script of the release is fetched instead.
install_self() {
	local src="$0" tag
	if [ "$DRY" = 1 ]; then dry "install this script as $SELF"; return 0; fi
	if [ -f "$src" ] && [ "$src" -ef "$SELF" ]; then return 0; fi
	if ! { [ -f "$src" ] && head -n 2 "$src" | grep -q 'Veilway installer and manager'; }; then
		release_tag "$CORE_REPO" "$NODE_PUBKEY" veilway
		tag="$TAG_OUT"
		download_verified "$CORE_REPO" "$NODE_PUBKEY" veilway.sh "$tag" veilway
		src="$TMP/veilway.sh"
		head -n 2 "$src" | grep -q 'Veilway installer and manager' || die "the fetched installer script is not the expected file"
	fi
	install -d -m 0755 "$(dirname "$SELF")"
	install -m 0755 -o root -g root "$src" "$SELF.new"
	mv -f "$SELF.new" "$SELF"
	step "installed $SELF"
}

# The panel runs unprivileged and never updates or restarts itself. It writes the word "panel", "node" or "both", or "restart-" and one of them, or "web-routes" after it wrote web-routes.json, to a file in $UPDATE_DIR, which only it and root can write. The path unit sees the file and starts the root service, which runs `panel-update-request`.
updater_units() {
	act install -d -m 0770 -o root -g veilway-panel "$UPDATE_DIR"
	act install -d -m 0700 -o root -g root "$BACKUP_DIR"
	write_unit "$UNIT_DIR/veilway-panel-update.path" <<EOF
[Unit]
Description=Veilway panel update request

[Path]
PathExists=$UPDATE_DIR/request
Unit=veilway-panel-update.service

[Install]
WantedBy=multi-user.target
EOF
	write_unit "$UNIT_DIR/veilway-panel-update.service" <<EOF
[Unit]
Description=Veilway update of the panel, the node or both, started by a request from the panel
Documentation=https://github.com/$PANEL_REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF panel-update-request
TimeoutStartSec=15min
NoNewPrivileges=true
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_SETUID CAP_SETGID
ProtectSystem=strict
ReadWritePaths=-$BIN_DIR -$(dirname "$SELF") -$UNIT_DIR -$VER_DIR -$BACKUP_DIR -$UPDATE_DIR -$CONF_DIR -/etc/caddy -/etc/nginx -/var/log/nginx
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true
SystemCallArchitectures=native
UMask=0022
EOF
}

# Run by the root service. The request carries no input: only the exact word "panel" counts, and it is deleted before anything runs. No version, path or argument is taken from it.
# Every update also replaces the saved installer with the one signed in the same release, so installer fixes reach servers installed earlier. The new copy is used from the next run.
update_self() {
	local tag cur vf
	if [ "$DRY" = 1 ]; then dry "download veilway.sh and veilway.sh.minisig of the core release, verify them and install them as $SELF"; return 0; fi
	release_tag "$CORE_REPO" "$NODE_PUBKEY" veilway
	tag="$TAG_OUT"
	cur="$(installed_version installer)"
	if [ -n "$cur" ] && [ "$cur" != "$tag" ] && semver_lower "$tag" "$cur" && [ "$ALLOW_DOWNGRADE" = 0 ]; then warn "the installer of $tag is older than the saved one of $cur: kept the saved one"; return 0; fi
	download_verified "$CORE_REPO" "$NODE_PUBKEY" veilway.sh "$tag" veilway
	head -n 2 "$TMP/veilway.sh" | grep -q 'Veilway installer and manager' || die "the fetched installer script is not the expected file"
	if cmp -s "$TMP/veilway.sh" "$SELF"; then info "the saved installer is the one of $tag"
	else
		install -d -m 0755 "$(dirname "$SELF")"
		install -m 0755 -o root -g root "$TMP/veilway.sh" "$SELF.new"
		mv -f "$SELF.new" "$SELF"
		step "updated $SELF to the installer of $tag, used from the next run"
	fi
	install -d -m 0755 "$VER_DIR"
	vf="$(mktemp "$VER_DIR/.installer.XXXXXX")"
	printf '%s\n' "$tag" >"$vf"; chmod 0644 "$vf"; mv -f "$vf" "$VER_DIR/installer.version"
}

do_panel_update_request() {
	local req="$UPDATE_DIR/request" word=""
	need_root
	if [ -f "$req" ] && [ ! -L "$req" ]; then word="$(timeout 5 head -c 16 -- "$req" 2>/dev/null | tr -d '\n' || true)"; fi
	act rm -f -- "$req"
	case "$word" in
		panel | node | both) ;;
		web-routes) do_web_routes; return 0 ;;
		# The panel's Restart buttons. A node restart drops every live tunnel for a moment.
		restart-node | restart-panel | restart-both) do_restart "${word#restart-}"; return 0 ;;
		*) warn "the update request was not panel, node, both, web-routes or a restart: ignored"; return 0 ;;
	esac
	# A service has no terminal to answer a question on: the admin said yes in the panel.
	ASSUME_YES=1
	do_update "$word"
}

install_panel() {
	local sub first=()
	step "panel"
	ensure_user veilway "$STATE_DIR"
	ensure_user veilway-panel "$PANEL_DIR"
	act install -d -m 0750 -o veilway-panel -g veilway-panel "$PANEL_DIR"
	act install -d -m 0750 -o root -g veilway "$CONF_DIR"
	fetch_and_install panel
	panel_config
	panel_unit
	updater_units
	install_self
	daemon_reload
	[ -z "$DOMAIN" ] && [ "$NO_DOMAIN" = 0 ] || web_setup
	# The panel stores these only where it has nothing yet, so a re-run never replaces what the operator set. The node address only goes in when the node is on this server, and the pin only for the self-signed endpoint on an IP address.
	if [ "$DRY" = 1 ]; then dry "fill the panel's node address and endpoint main from this install, where the panel has none"
	else
		sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
		[ -z "$HTTPS_HOST" ] || first=(--endpoint-url "https://$HTTPS_HOST${sub:-/sub}/main")
		[ -z "$HTTPS_HOST" ] || [ "$NO_DOMAIN" = 0 ] || first+=(--endpoint-pin "$(web_state pin)")
		[ "${1:-}" != both ] || [ -z "${DOMAIN:-$PUBLIC_IP}" ] || first+=(--node-host "${DOMAIN:-$PUBLIC_IP}")
		if [ "${#first[@]}" -gt 0 ]; then as_panel_user "$BIN_DIR/veilway-panel" first-run --config "$CONF_DIR/panel.json" "${first[@]}" || warn "the panel did not take its node address and endpoint: add them under Settings (a panel older than the release that has first-run cannot)"; fi
	fi
	svc enable veilway-panel.service
	svc enable veilway-panel-update.path
	svc start veilway-panel-update.path
	svc restart veilway-panel.service
	panel_summary
}

# Written once: an existing panel.json is never touched. The prefix is random, so the admin pages are not at a guessable path.
panel_config() {
	local f="$CONF_DIR/panel.json" prefix
	if [ "$DRY" = 1 ]; then dry "write $f (loopback 127.0.0.1:$PANEL_PORT, random prefix, keys and database under $PANEL_DIR)"; return 0; fi
	[ -f "$f" ] && { info "kept existing $f"; return 0; }
	prefix="/$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	cat >"$f" <<EOF
{
	"listen": "127.0.0.1:$PANEL_PORT",
	"prefix": "$prefix",
	"sub_path": "/sub",
	"database": "$PANEL_DIR/panel.db",
	"keys": "$PANEL_DIR/panel.keys",
	"signing": "$PANEL_DIR/signing.keys",
	"gateway": "$PANEL_DIR/gateway.keys",
	"gateway_next": "$PANEL_DIR/gateway.next",
	"node_socket": "/run/veilway/control.sock",
	"trusted_proxies": ["127.0.0.1", "::1"],
	"allowed_hosts": [],
	"secure_cookies": true,
	"two_step": "$TWO_STEP"
}
EOF
	chown root:veilway-panel "$f"
	chmod 0640 "$f"
	step "wrote $f"
}

panel_summary() {
	local token="" prefix="/panel" sub="/sub" i from to moved lines=()
	if [ -f "$CONF_DIR/panel.json" ]; then
		prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
		sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
	fi
	if [ "$DRY" != 1 ] && has_systemd; then
		for i in 1 2 3 4 5 6 7 8 9 10; do
			# Only this run of the panel: a token printed by an earlier run, or an earlier install, is no longer valid.
			token="$(journalctl -u veilway-panel _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value veilway-panel 2>/dev/null)" --no-pager -o cat 2>/dev/null | sed -n 's/^Setup token (one time): //p' | tail -n 1 || true)"
			[ -n "$token" ] && break
			sleep 1
		done
	fi
	printf '\n'
	if [ "$NO_DOMAIN" = 1 ]; then
		lines=("Admin pages: not on the internet. Open them through an SSH tunnel from your computer:" "  ssh -L 8480:127.0.0.1:$PANEL_PORT root@$PUBLIC_IP" "Then open http://localhost:8480$prefix/ in your browser.")
		if [ -n "$token" ]; then lines+=("Setup token (one time): $token"); else lines+=("Setup token: sudo journalctl -u veilway-panel | grep 'Setup token'"); fi
		lines+=("Open the admin pages in a browser and paste the token there." "It asks for your username, password and the terms." "")
		lines+=("Subscriptions: https://$HTTPS_HOST$sub/main, self-signed." "Add it under Settings > Endpoints: name main, URL https://$HTTPS_HOST$sub/main, pin $(web_state pin)" "The apps check that pin, so the self-signed certificate is safe for your users." "Never open the admin pages over https://$PUBLIC_IP: only the tunnel is meant for them." "")
		lines+=("Web server: $WEB, site file $([ "$WEB" = caddy ] && echo "$CADDY_SITE" || echo "$NGINX_SITE"), serves $sub only." "Remove it all with: sudo bash veilway.sh uninstall web")
		box "Panel" "${lines[@]}"
		return 0
	fi
	if [ -n "$DOMAIN" ]; then
		lines=("Admin pages: https://$HTTPS_HOST$prefix/")
		if [ -n "$token" ]; then lines+=("Setup token (one time): $token"); else lines+=("Setup token: sudo journalctl -u veilway-panel | grep 'Setup token'"); fi
		lines+=("Open the admin pages in a browser and paste the token there." "It asks for your username, password and the terms." "")
		lines+=("Web server: $WEB, site file $([ "$WEB" = caddy ] && echo "$CADDY_SITE" || echo "$NGINX_SITE")")
		lines+=("  $prefix and $sub go to the panel; every other path shows a plain site." "  The plain site $WEB_ROOT/index.html was drawn for this server." "  Put a page of your own there: a real site hides the server best." "  It is also served over http on 127.0.0.1:$DECOY_PORT (this machine only) for a node's decoy origin." "  A transport behind $WEB (ws, fronted) needs its path added to the site file: the panel shows the lines." "  The panel's not_found is now $WEB's own 404, so the panel paths look" "  like any other missing page.")
		if [ "$WEB" = caddy ]; then lines+=("  Caddy gets and renews the certificate for $DOMAIN by itself."); else lines+=("  certbot renews the certificate with its own timer."); fi
		lines+=("  Port 80 must stay reachable: the certificate is checked over it.")
		moved="$(web_state node_moved)"; [ -n "$moved" ] || [ -z "$(web_state node_443_moved)" ] || moved="443 8443"; if [ -n "$moved" ]; then read -r from to <<<"$moved"; lines+=("The node's TCP transports moved from $from to $to: publish the profiles again."); fi
		lines+=("Remove it all with: sudo bash veilway.sh uninstall web")
		box "Panel" "${lines[@]}"
		return 0
	fi
	box "Panel" \
		"Listens on 127.0.0.1:$PANEL_PORT only. Put your web server in front:" \
		"" \
		"  nginx:  location ~ ^($prefix|$sub)(/|\$) {" \
		"            proxy_pass http://127.0.0.1:$PANEL_PORT;" \
		"            client_max_body_size 100m;" \
		"            proxy_set_header Host \$http_host;" \
		"            proxy_set_header X-Forwarded-For \$remote_addr; }" \
		"" \
		"  Caddy:  panel.example.com {" \
		"            reverse_proxy $prefix/* 127.0.0.1:$PANEL_PORT" \
		"            reverse_proxy $sub/* 127.0.0.1:$PANEL_PORT }" \
		"" \
		"HTTPS is required: the panel signs in only over it." \
		"  Caddy gets a certificate for your domain by itself." \
		"  nginx: sudo apt install certbot python3-certbot-nginx" \
		"         sudo certbot --nginx -d your-domain" \
		"" \
		"Admin pages: https://your-domain$prefix/" \
		"$([ -n "$token" ] && echo "Setup token (one time): $token" || echo "Setup token: sudo journalctl -u veilway-panel | grep 'Setup token'")" \
		"Open the admin pages in a browser and paste the token there." \
		"It asks for your username, password and the terms."
}

# Moves the admin pages to a new path, a random one or the one given. The web server in front has to follow, so its new lines are printed; a panel that does not come back up gets the old path again.
do_panel_prefix() {
	local f="$CONF_DIR/panel.json" new="${1:-}" old sub host="your-domain" port
	need_root
	[ -f "$f" ] || die "no panel is installed: $f is missing"
	old="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$f")"; sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$f")"
	[ -n "$new" ] || new="/$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	port="$(web_state https_port)"; [ -z "$port" ] || [ "$port" = 443 ] || host+=":$port"
	[[ "$new" =~ ^/[A-Za-z0-9._/-]*[A-Za-z0-9._-]$ && "$new" != *//* && "$new" != *..* ]] || die "the path must start with /, end without one, and hold only letters, digits, -, _, . and /"
	[[ "$new" != "$sub" && "$new/" != "$sub/"* && "$sub/" != "$new/"* ]] || die "the path must not be, sit inside or hold the subscription path $sub"
	[ "$new" != "$old" ] || die "the admin pages are already at $new"
	confirm "Move the admin pages from $old to $new? Bookmarks and your web server's config must follow." || die "cancelled"
	if [ "$DRY" = 1 ]; then dry "set prefix to $new in $f and restart veilway-panel"; return 0; fi
	backup_file "$f"
	sed -i "s|\"prefix\": *\"[^\"]*\"|\"prefix\": \"$new\"|" "$f"
	svc restart veilway-panel.service
	sleep 2
	if has_systemd && ! systemctl is-active --quiet veilway-panel.service; then
		sed -i "s|\"prefix\": *\"[^\"]*\"|\"prefix\": \"$old\"|" "$f"
		svc restart veilway-panel.service
		die "the panel did not start with $new, so it is back at $old: see sudo journalctl -u veilway-panel"
	fi
	step "the admin pages are now at $new"
	if [ "$(web_state mode)" = ip ]; then box "Panel path" "The admin pages stay on the SSH tunnel: nothing is added to your web server." "" "  ssh -L 8480:127.0.0.1:$PANEL_PORT root@$(web_state ip)" "" "Admin pages: http://localhost:8480$new/"
	else box "Panel path" "Change the path in your web server's config, then reload it:" "" "  nginx:  location ~ ^($new|$sub)(/|\$) {" "  Caddy:  reverse_proxy $new/* 127.0.0.1:$PANEL_PORT" "" "Admin pages: https://$host$new/"; fi
}

pick_component() {
	case "${1:-}" in
		node | panel | both | mirror) printf '%s' "$1" ;;
		"") printf '%s' "$(ask "Install node, panel, or both? [both]" both)" ;;
		*) die "choose node, panel, both or mirror" ;;
	esac
}

# The web server questions and the checks of its settings, for install and for the menu's Web server entry. WEB_NOW=1 skips the first yes or no, for a caller that already asked it.
web_plan() {
	local comp="$1" port detected
	if [ -z "$DOMAIN" ] && [ -z "$WEB" ] && [ "$NO_DOMAIN" = 0 ] && { [ "$comp" = panel ] || [ "$comp" = both ]; } && [ "$ASSUME_YES" = 0 ] && [ "$DRY" = 0 ] && { : </dev/tty; } 2>/dev/null; then
		[ "$WEB_NOW" = 1 ] || wiz 2 "Web server"
		if [ "$WEB_NOW" = 1 ] || confirm "Set up a web server with HTTPS for the panel now? It needs a domain name that points at this server."; then
			DOMAIN="$(ask "Domain name:" "")"
			if [ -n "$DOMAIN" ]; then
				WEB="$(ask "Web server, caddy or nginx? [caddy]" caddy)"
				HTTPS_PORT="$(web_state https_port)"; HTTPS_PORT="$(ask "HTTPS port? [${HTTPS_PORT:-443}]" "${HTTPS_PORT:-443}")"
			else info "no domain name given: no web server is set up"; fi
		elif confirm "No domain name? Then the subscriptions are served on this server's IP, with a self-signed certificate that the apps check by its pin."; then NO_DOMAIN=1
		fi
	fi
	[ -z "$WEB" ] || [ -n "$DOMAIN" ] || [ "$NO_DOMAIN" = 1 ] || die "--web needs --domain or --no-domain"
	[ -z "$HTTPS_PORT" ] || [ -n "$DOMAIN" ] || [ "$NO_DOMAIN" = 1 ] || die "--https-port needs --domain or --no-domain"
	if [ "$NO_DOMAIN" = 1 ]; then
		port=443; if has ss && [ -n "$(ss -H -ltn "sport = :443" 2>/dev/null)" ]; then port=8443; fi
		detected="$(ip -4 -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' || true)"
		# nginx by default: it serves the certificate whatever the SNI, which apps leave out for an IP, and opens no port 80.
		[ -n "$WEB" ] || WEB="$(ask "Web server, nginx or caddy? [nginx]" nginx)"
		[ -n "$HTTPS_PORT" ] || HTTPS_PORT="$(ask "Port for the subscriptions? [$port]" "$port")"
		IP_GIVEN=0; [ -z "$PUBLIC_IP" ] || IP_GIVEN=1
		[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(ask "This server's IPv4 address? [$detected]" "$detected")"
		[[ "$PUBLIC_IP" =~ $IPV4_RE ]] || die "\"$PUBLIC_IP\" is not an IPv4 address: pass it with --ip <address>"
		# On a cloud with NAT the address this server sees is a private one, which apps outside cannot reach. One given with --ip is the operator's choice, for a server only reached at home.
		if [[ "$PUBLIC_IP" =~ $PRIVATE_RE ]] && [ "$IP_GIVEN" = 0 ]; then
			{ [ "$ASSUME_YES" = 0 ] && [ "$DRY" = 0 ]; } || die "this server sees the private address $PUBLIC_IP: pass the address apps reach it at with --ip <address> (a private one too, for a server used only at home)"
			PUBLIC_IP="$(ask "This server sees the private address $PUBLIC_IP. Apps outside cannot reach it, only devices on the same network. The address apps reach it at? [$PUBLIC_IP]" "$PUBLIC_IP")"
			[[ "$PUBLIC_IP" =~ $IPV4_RE ]] || die "\"$PUBLIC_IP\" is not an IPv4 address: pass it with --ip <address>"
		fi
		if [[ "$PUBLIC_IP" =~ $PRIVATE_RE ]]; then warn "$PUBLIC_IP is a private address: only devices on the same network can use these subscriptions, and the apps ask before they connect to it"; fi
	fi
	if [ -n "$(web_state web)" ] && { [ -n "$DOMAIN" ] || [ "$NO_DOMAIN" = 1 ]; }; then
		if [ "$(web_state mode)" = ip ]; then [ "$NO_DOMAIN" = 1 ] || die "the web server here serves the subscriptions on an IP address: run sudo bash veilway.sh uninstall web first"
		else [ "$NO_DOMAIN" = 0 ] || die "the web server here serves a domain: run sudo bash veilway.sh uninstall web first"; fi
	fi
	if [ -n "$DOMAIN" ] || [ "$NO_DOMAIN" = 1 ]; then
		if [ -n "$DOMAIN" ]; then
			DOMAIN="${DOMAIN,,}"
			[[ "$DOMAIN" =~ $DOMAIN_RE ]] || die "\"$DOMAIN\" is not a domain name: use something like panel.example.com"
		fi
		WEB="${WEB:-caddy}"
		[ "$WEB" = caddy ] || [ "$WEB" = nginx ] || die "--web is caddy or nginx"
		HTTPS_PORT="${HTTPS_PORT:-$(web_state https_port)}"; HTTPS_PORT="${HTTPS_PORT:-443}"
		[[ "$HTTPS_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$HTTPS_PORT))" -ge 1 ] && [ "$((10#$HTTPS_PORT))" -le 65535 ] || die "--https-port must be a port from 1 to 65535"
		HTTPS_PORT=$((10#$HTTPS_PORT))
		[ "$HTTPS_PORT" != 80 ] || die "port 80 cannot be the HTTPS port: the certificate is checked over port 80"
		[ "$HTTPS_PORT" != "$PANEL_PORT" ] || die "port $PANEL_PORT is the panel's own port on 127.0.0.1: pick another --https-port"
		HTTPS_HOST="${DOMAIN:-$PUBLIC_IP}"; [ "$HTTPS_PORT" = 443 ] || HTTPS_HOST+=":$HTTPS_PORT"
		web_preflight
	fi
}

do_install() {
	local what comp ui=0 lines=()
	[ "$ASSUME_YES" = 0 ] && [ "$DRY" = 0 ] && { : </dev/tty; } 2>/dev/null && ui=1
	if [ -z "${1:-}" ] && [ "$ui" = 1 ]; then
		wiz 1 "What to install"
		pick 6 cancel "both|Node and panel: one server for everything" "node|Node: the VPN server only" "panel|Panel: the web panel for nodes and users" "mirror|Mirror: a copy of the releases for people who cannot reach GitHub" || die "cancelled"
		comp="$PICKED"
	else comp="$(pick_component "${1:-}")"; fi
	what="$comp"
	need_root
	refuse_links
	detect_target
	ensure_tools
	[ -z "$DOMAIN" ] || [ "$comp" = panel ] || [ "$comp" = both ] || die "--domain is for install panel or install both"
	[ "$NO_DOMAIN" = 0 ] || [ "$comp" = panel ] || [ "$comp" = both ] || die "--no-domain is for install panel or install both"
	[ "$NO_DOMAIN" = 0 ] || [ -z "$DOMAIN" ] || die "--no-domain and --domain cannot be used together"
	[ -z "$PUBLIC_IP" ] || [ "$NO_DOMAIN" = 1 ] || die "--ip needs --no-domain"
	web_plan "$comp"
	# Two-step sign-in is on unless the operator says no at a fresh install of the panel, and the question's default is yes. --no-two-step says no for a script. A panel that has its config keeps it: the switch is then only in that file.
	if [ "$TWO_STEP" = off ] && [ -f "$CONF_DIR/panel.json" ]; then warn "--no-two-step only applies to a fresh install: $CONF_DIR/panel.json is kept as it is"
	elif { [ "$comp" = panel ] || [ "$comp" = both ]; } && [ ! -f "$CONF_DIR/panel.json" ] && [ "$ASSUME_YES" = 0 ] && [ "$DRY" = 0 ] && { : </dev/tty; } 2>/dev/null; then
		wiz 3 "Sign-in"
		case "$(ask "Ask for an authenticator code at sign-in (two-step sign-in)? Recommended: without it, anyone who learns the admin password gets the panel, the node and every user's link. [Y/n]" y | tr '[:upper:]' '[:lower:]')" in n | no) TWO_STEP=off ;; esac
	fi
	[ "$TWO_STEP" = on ] || [ -f "$CONF_DIR/panel.json" ] || warn "two-step sign-in will be off: the panel asks for the password only. Not recommended for a panel with real users. To turn it on later, see \"Two-step sign-in off\" in the panel manual"
	if [ "$ui" = 1 ]; then
		wiz 4 "Check and go"
		lines=("Install       ${comp/both/node and panel}" "Release       ${WANT_VERSION:-the newest signed release}")
		if [ "$comp" = panel ] || [ "$comp" = both ]; then
			if [ -n "$DOMAIN" ]; then lines+=("Web server    $WEB for $DOMAIN, https port $HTTPS_PORT" "Ports         panel 127.0.0.1:$PANEL_PORT, plain site 127.0.0.1:$DECOY_PORT, 80 for the certificate")
			elif [ "$NO_DOMAIN" = 1 ]; then lines+=("Web server    $WEB on $PUBLIC_IP, https port $HTTPS_PORT, self-signed" "Ports         panel 127.0.0.1:$PANEL_PORT, plain site 127.0.0.1:$DECOY_PORT")
			else lines+=("Web server    none: the panel listens on 127.0.0.1:$PANEL_PORT only"); fi
			if [ -f "$CONF_DIR/panel.json" ]; then lines+=("Two-step      kept as $CONF_DIR/panel.json has it"); else lines+=("Two-step      $TWO_STEP"); fi
		fi
		lines+=("" "Nothing changes until you answer yes.")
		box "Summary" "${lines[@]}"
		case "$(ask "Go on? [Y/n]" y | tr '[:upper:]' '[:lower:]')" in n | no) die "cancelled" ;; esac
	fi
	[ "$DRY" = 1 ] || { TMP="$(mktemp -d)"; install -d -m 0755 "$STATE_DIR" 2>/dev/null || true; }
	has_systemd || [ "$DRY" = 1 ] || warn "systemd is not running: units are written but nothing is started"
	[ "$DRY" = 1 ] || { mkdir -p "$STATE_DIR" "$PANEL_DIR"; }
	case "$what" in
		node) install_node ;;
		panel) install_panel ;;
		both) install_node; install_panel both ;;
		mirror) install_mirror ;;
	esac
	[ "$what" != node ] || [ "$DRY" = 1 ] || info "to let a panel manage this node, run: sudo -u veilway $BIN_DIR/veilway link answer --config $NODE_DIR/config.json --tag panel --apply=/run/veilway/control.sock"
	printf '\n'
	step "done. Check the state any time with: sudo bash veilway.sh status"
}

do_update() {
	local comp="${1:-both}" cur web decoy sha
	need_root
	refuse_links
	detect_target
	ensure_tools
	[ "$DRY" = 1 ] || TMP="$(mktemp -d)"
	if [ "$comp" = node ] || [ "$comp" = both ]; then
		if [ -x "$BIN_DIR/veilway" ] || [ "$DRY" = 1 ]; then
			cur="$(installed_version node)"
			info "node is at ${cur:-unknown}"
			fetch_and_install node
			fetch_geoip
			prepare_node_dir
			node_unit
			if [ -f "$UNIT_DIR/veilway-xray.service" ]; then xray_units; xray_node_group; fi
			daemon_reload
			[ -f "$UNIT_DIR/veilway-mirror.service" ] && svc restart veilway-mirror.service
			svc restart veilway.service
		else info "node is not installed, skipped"; fi
	fi
	# The node starts only the Xray-core it pins, so an add-on of another release would stop Xray's users after this update. It is installed again here; an add-on installed before v0.3.4 has no release file and counts as another release.
	if [ -x "$ADDON_DIR/xray/xray" ] && [ "$(cat "$ADDON_DIR/xray/release" 2>/dev/null)" != "$XRAY_RELEASE" ]; then
		info "the Xray add-on is not Xray-core $XRAY_RELEASE, which this node pins: installing it again"
		( do_addon xray install ) || warn "the Xray add-on could not be installed again: run sudo bash veilway.sh addon xray install, or Xray's users stay cut off"
	fi
	if [ "$comp" = mirror ]; then
		if [ -f "$UNIT_DIR/veilway-mirror.service" ] || [ "$DRY" = 1 ]; then
			info "node binary is at $(installed_version node || true)"
			fetch_and_install node
			mirror_unit
			daemon_reload
			svc restart veilway-mirror.service
		else info "mirror is not installed, skipped"; fi
	fi
	if [ "$comp" = panel ] || [ "$comp" = both ]; then
		if [ -x "$BIN_DIR/veilway-panel" ] || [ "$DRY" = 1 ]; then
			cur="$(installed_version panel)"
			info "panel is at ${cur:-unknown}"
			fetch_and_install panel
			panel_unit
			updater_units
			install_self
			daemon_reload
			svc enable veilway-panel-update.path
			svc start veilway-panel-update.path
			svc restart veilway-panel.service
		else info "panel is not installed, skipped"; fi
	fi
	web="$(web_state web)"
	# A web setup from before v0.2.15 has no decoy origin, and its site file is the operator's to edit, so the decoy goes in a file of its own.
	if [ -f "$WEB_STATE" ] && { [ "$web" = caddy ] || [ "$web" = nginx ]; }; then
		if [ -n "$(ss -H -ltnp "sport = :$DECOY_PORT" | grep -vE '"(caddy|nginx)"' || true)" ]; then warn "127.0.0.1:$DECOY_PORT is used by something else here, so the plain site is not served there. A node's decoy origin needs a web page: pick another port with VEILWAY_DECOY_PORT=<port> and run update again, or point the origin at your own page."
		elif [ -z "$(ss -H -ltn "sport = :$DECOY_PORT")" ]; then
			web_decoy
			if [ "$web" = caddy ]; then
				decoy="$CADDY_DECOY"
				write_unit "$decoy" <<EOF
# Written by veilway.sh update. Remove it with: sudo bash veilway.sh uninstall web
http://:$DECOY_PORT {
	bind 127.0.0.1
	root * $WEB_ROOT
	file_server
}
EOF
			else
				decoy="$NGINX_DECOY"
				write_unit "$decoy" <<EOF
# Written by veilway.sh update. Remove it with: sudo bash veilway.sh uninstall web
server {
	listen 127.0.0.1:$DECOY_PORT;
	server_tokens off;
	root $WEB_ROOT;
	location / {
		try_files \$uri \$uri/ =404;
	}
}
EOF
			fi
			if [ "$DRY" = 1 ]; then dry "check the $web config, reload $web and note $decoy in $WEB_STATE"
			elif { [ "$web" = caddy ] && caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; } || { [ "$web" = nginx ] && nginx -t >/dev/null 2>&1; }; then
				web_note decoy_file "$decoy"
				if systemctl is-active --quiet "$web.service" 2>/dev/null; then svc reload "$web.service"; fi
				step "$web now serves the plain site over http on 127.0.0.1:$DECOY_PORT (this machine only), the default decoy origin of a node's transports"
			else
				rm -f -- "$decoy"
				warn "$web did not accept the decoy site on 127.0.0.1:$DECOY_PORT, so it was taken back: a node's decoy origin needs a web page there, add one by hand"
			fi
		fi
		# Before v0.3.3 every install wrote the same page, so a search for it found Veilway servers. A page nobody edited is drawn again for this server; an edited one is never touched.
		sha="$(web_state decoy_sha)"
		if [ -n "$sha" ] && [ -f "$WEB_ROOT/index.html" ] && [ "$(sha256sum "$WEB_ROOT/index.html" | cut -d' ' -f1)" = "$sha" ] && grep -q "<title>Notes from the garden</title>" "$WEB_ROOT/index.html"; then
			if [ "$DRY" = 1 ]; then dry "draw a new plain page for this server in place of the one every install shared"; else rm -f -- "$WEB_ROOT/index.html"; web_decoy; fi
		fi
		# Before v0.3.1 Caddy's decoy site answered only the host 127.0.0.1, and the node passes on the visitor's own host, so a prober got an empty 200 at a transport's path where any other path gets the site's 404.
		for decoy in "$CADDY_SITE" "$CADDY_DECOY"; do
			if [ "$web" = caddy ] && [ -f "$decoy" ] && grep -q "^http://127.0.0.1:$DECOY_PORT {\$" "$decoy"; then
				if [ "$DRY" = 1 ]; then dry "let the decoy site in $decoy answer every host name, and reload caddy"; continue; fi
				act sed -i "s#^http://127.0.0.1:$DECOY_PORT {\$#http://:$DECOY_PORT {#" "$decoy"
				if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then svc reload caddy.service; step "the decoy site in $decoy now answers every host name, as the site does"
				else act sed -i "s#^http://:$DECOY_PORT {\$#http://127.0.0.1:$DECOY_PORT {#" "$decoy"; warn "caddy did not accept the decoy site for every host name in $decoy, so it was put back"; fi
			fi
		done
		web_routes_include "$web" || true
	fi
	update_self
	warn "a node restart drops every live tunnel for a moment"
}

unit_state() {
	has_systemd || { printf 'no systemd'; return; }
	local a e
	a="$(systemctl is-active "$1" 2>/dev/null || true)"
	e="$(systemctl is-enabled "$1" 2>/dev/null || true)"
	printf '%s, %s' "${a:-unknown}" "${e:-not installed}"
}

do_status() {
	local v prefix host port line sub
	header
	printf '  %s%-14s %-34s %s%s\n' "$B" "Part" "State" "Version" "$Z"
	printf '  %s%s%s\n' "$D" "$(rule 62)" "$Z"
	v="$(installed_version node)"; v="${v:--}"
	[ -x "$BIN_DIR/veilway" ] || v="not installed"
	printf '  %-14s %-34s %s\n' "node" "$(unit_state veilway.service)" "$v"
	v="$(installed_version panel)"; v="${v:--}"
	[ -x "$BIN_DIR/veilway-panel" ] || v="not installed"
	printf '  %-14s %-34s %s\n' "panel" "$(unit_state veilway-panel.service)" "$v"
	[ -f "$UNIT_DIR/veilway-mirror.service" ] && printf '  %-14s %-34s %s\n' "mirror" "$(unit_state veilway-mirror.service)" "$MIRROR_DIR/mirror.json"
	printf '  %-14s %-34s %s\n' "config" "$([ -f "$NODE_DIR/config.json" ] && echo present || echo missing)" "$NODE_DIR/config.json"
	printf '  %-14s %-34s %s\n' "state" "$([ -d "$STATE_DIR" ] && echo present || echo missing)" "$STATE_DIR"
	printf '  %-14s %-34s %s\n' "backups" "$(find "$BACKUP_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ') files" "$BACKUP_DIR"
	if [ -r "$CONF_DIR/panel.json" ]; then
		prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
		host="$(web_state domain)"; port="$(web_state https_port)"
		[ -z "$host" ] || [ -z "$port" ] || [ "$port" = 443 ] || host="$host:$port"
		sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
		if [ "$(web_state mode)" = ip ]; then
			printf '\n  %-14s %s\n' "admin pages" "http://localhost:8480$prefix/ through: ssh -L 8480:127.0.0.1:$PANEL_PORT root@$(web_state ip)"
			printf '  %-14s %s\n' "endpoint" "https://$(web_state ip)$([ "$port" = 443 ] || echo ":$port")$sub/main, pin $(web_state pin)"
		else printf '\n  %-14s %s\n' "admin pages" "https://${host:-your-domain}$prefix/"; fi
		printf '  %-14s %s\n' "subscriptions" "$sub"
		[ -x "$BIN_DIR/veilway-panel" ] && as_panel_user "$BIN_DIR/veilway-panel" admins --config "$CONF_DIR/panel.json" 2>/dev/null | while IFS= read -r line; do printf '  %-14s %s\n' "admin" "$line"; done
	fi
	printf '\n'
}

# Lists the panel's admins, or gives one a new password from this console, for an operator locked out of the panel. Their sessions end; the authenticator stays.
do_admin() {
	local name="${2:-}" pw pw2
	[ -x "$BIN_DIR/veilway-panel" ] && [ -f "$CONF_DIR/panel.json" ] || die "no panel is installed here"
	if [ "${1:-list}" = list ]; then as_panel_user "$BIN_DIR/veilway-panel" admins --config "$CONF_DIR/panel.json" || die "the admins could not be listed: the reason is above, and a panel older than v0.2.5 does not have this command"; return 0; fi
	[ "$1" = reset ] || die "try: admin list, or admin reset <username>"
	[ -n "$name" ] || name="$(ask "Username:" "")"
	[ -n "$name" ] || die "give the username: admin reset <username>"
	if [ "$DRY" = 1 ]; then dry "set a new password for $name"; return 0; fi
	[ -r /dev/tty ] || die "no terminal to ask for the password on"
	read -r -s -p "  New password for $name (12 characters or more): " pw </dev/tty; printf '\n'
	read -r -s -p "  The same again: " pw2 </dev/tty; printf '\n'
	[ "$pw" = "$pw2" ] || die "the two passwords differ, nothing was changed"
	printf '%s\n' "$pw" | as_panel_user "$BIN_DIR/veilway-panel" reset-password "$name" --config "$CONF_DIR/panel.json" || die "the password was not changed"
}

do_logs() {
	local unit="veilway.service"
	[ "${1:-node}" = panel ] && unit="veilway-panel.service"
	[ "${1:-node}" = mirror ] && unit="veilway-mirror.service"
	has_systemd || die "logs come from journald, and systemd is not running here"
	if [ "$DRY" = 1 ]; then dry "journalctl -u $unit -n 100 -f"; return 0; fi
	exec journalctl -u "$unit" -n 100 -f --no-pager
}

do_restart() {
	local comp="${1:-both}"
	need_root
	if [ "$comp" = mirror ]; then svc restart veilway-mirror.service; return 0; fi
	[ "$comp" = panel ] || svc restart veilway.service
	[ "$comp" = node ] || svc restart veilway-panel.service
}

node_flags() { printf '%s\n' --config "$NODE_DIR/config.json" --state "$STATE_DIR/veilway-state.json" --replay "$STATE_DIR/veilway-replay" --api /run/veilway/control.sock; }

as_mirror_user() { setpriv --reuid veilway-mirror --regid veilway-mirror --clear-groups "$@"; }
# The panel's own user and groups, as its service has them, so the database and its log files keep their owner.
as_panel_user() { setpriv --reuid veilway-panel --regid veilway-panel --groups veilway "$@"; }

as_mirror() {
	if [ "$(id -u)" = 0 ] && has setpriv; then as_mirror_user "$BIN_DIR/veilway" "$@"
	else "$BIN_DIR/veilway" "$@"; fi
}

# Runs veilway as the service user so the file checks match what the service sees.
as_node() {
	if [ "$(id -u)" = 0 ] && has setpriv; then setpriv --reuid veilway --regid veilway --clear-groups "$BIN_DIR/veilway" "$@"
	else "$BIN_DIR/veilway" "$@"; fi
}

run_check() {
	if [ "$DRY" = 1 ]; then dry "veilway check of $NODE_DIR/config.json as the service user"; return 0; fi
	[ -x "$BIN_DIR/veilway" ] || die "the node is not installed"
	[ -f "$NODE_DIR/config.json" ] || die "no $NODE_DIR/config.json yet"
	as_node check --config "$NODE_DIR/config.json"
}

do_doctor() {
	local flags
	[ -x "$BIN_DIR/veilway" ] || die "the node is not installed"
	if [ "$DRY" = 1 ]; then dry "veilway doctor with the service's paths"; return 0; fi
	mapfile -t flags < <(node_flags)
	as_node doctor "${flags[@]}"
}

backup_paths() { printf '%s\n' "${CONF_DIR#/}" "${STATE_DIR#/}/veilway-state.json" "${PANEL_DIR#/}" "${MIRROR_DIR#/}"; }

do_backup() {
	local out="${1:-$BACKUP_DIR/veilway-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}" p existing=()
	need_root
	while read -r p; do [ -e "/$p" ] && existing+=("$p"); done < <(backup_paths)
	[ "${#existing[@]}" -gt 0 ] || { warn "nothing to back up yet"; return 0; }
	# The replay memory is left out on purpose: restoring an old one would let old packets replay.
	if [ "$DRY" = 1 ]; then dry "tar czf $out ${existing[*]}"; return 0; fi
	mkdir -p "$(dirname "$out")"
	chmod 0700 "$(dirname "$out")" 2>/dev/null || true
	# The panel's database is copied with the panel stopped, so the archive never holds a half-written database and its log.
	local panel_up=0
	has_systemd && systemctl is-active --quiet veilway-panel.service && panel_up=1
	[ "$panel_up" = 1 ] && svc stop veilway-panel.service
	(umask 077; tar -czf "$out" -C / "${existing[@]}") || { [ "$panel_up" = 1 ] && svc start veilway-panel.service; die "writing $out failed"; }
	[ "$panel_up" = 1 ] && svc start veilway-panel.service
	step "backup written to $out (holds keys: keep it private)"
}

do_restore() {
	local file="${1:-}" names listing
	need_root
	refuse_links
	[ -n "$file" ] || die "usage: veilway.sh restore <backup.tar.gz>"
	[ -r "$file" ] || [ "$DRY" = 1 ] || die "cannot read $file"
	confirm_typed restore "Restore $file over $CONF_DIR, the usage state and the panel data?" || die "cancelled"
	if [ "$DRY" = 1 ]; then dry "stop services, save current files to $BACKUP_DIR, extract $file to /, fix owners, start services"; return 0; fi
	TMP="$(umask 077; mktemp -d)"
	cp -- "$file" "$TMP/archive.tar.gz"
	file="$TMP/archive.tar.gz"
	names="$(tar -tzf "$file")" || die "$file is not a readable gzip archive: refusing, nothing was stopped"
	listing="$(tar -tvzf "$file")" || die "$file cannot be listed: refusing, nothing was stopped"
	[ -n "$names" ] || die "the archive is empty: refusing"
	grep -qvE '^[-d]' <<<"$listing" && die "the archive has links, devices or pipes: refusing"
	grep -qE '^.{3}[sS]|^.{6}[sS]' <<<"$listing" && die "the archive has setuid or setgid files: refusing"
	grep -qE '(^/|(^|/)\.\.(/|$))' <<<"$names" && die "the archive has unsafe paths: refusing"
	grep -qvE "^(${CONF_DIR#/}|${STATE_DIR#/}/veilway-state\.json|${PANEL_DIR#/})(/|$)" <<<"$names" && die "the archive has files outside Veilway's folders: refusing"
	do_backup "$BACKUP_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" || true
	svc stop veilway.service; svc stop veilway-panel.service
	trap 'svc start veilway.service || true; svc start veilway-panel.service || true; die "restore failed: the services were started again"' ERR
	rm -f -- "$PANEL_DIR/panel.db-wal" "$PANEL_DIR/panel.db-shm"
	tar -xzf "$file" -C / --no-same-owner --no-same-permissions
	id veilway >/dev/null 2>&1 && { chown root:veilway "$CONF_DIR"; chmod 0750 "$CONF_DIR"; prepare_node_dir; chown -h -R veilway:veilway "$NODE_DIR"; chown -h veilway:veilway "$STATE_DIR/veilway-state.json" 2>/dev/null || true; }
	chown -h root:veilway-panel "$CONF_DIR/panel.json" 2>/dev/null || true
	id veilway-panel >/dev/null 2>&1 && chown -h -R veilway-panel:veilway-panel "$PANEL_DIR"
	trap - ERR
	svc start veilway.service; svc start veilway-panel.service
	step "restored from $1"
}

do_uninstall() {
	need_root
	confirm_typed uninstall "Remove Veilway binaries, units, users and this installer? Backups in $BACKUP_DIR stay." || die "cancelled"
	do_backup || true
	# Only the units this server has, so parts that were never installed print nothing.
	for u in veilway-mirror.service veilway.service veilway-panel.service veilway-panel-update.path veilway-panel-update.service veilway-xray.socket veilway-xray.service; do
		[ -e "$UNIT_DIR/$u" ] || continue
		svc stop "$u" || true; svc disable "$u" 2>/dev/null || true
	done
	act rm -f "$UNIT_DIR/veilway.service" "$UNIT_DIR/veilway-panel.service" "$UNIT_DIR/veilway-panel-update.path" "$UNIT_DIR/veilway-panel-update.service" "$UNIT_DIR/veilway-xray.socket" "$UNIT_DIR/veilway-xray.service" "$UNIT_DIR/veilway-mirror.service" "$BIN_DIR/veilway" "$BIN_DIR/veilway-panel"
	act rm -rf "$ADDON_DIR"
	act rm -f "$GEOIP_FILE"
	daemon_reload
	if confirm "Also delete $CONF_DIR, $STATE_DIR, $PANEL_DIR and $MIRROR_DIR? The backup above keeps a copy."; then
		act rm -rf "$CONF_DIR" "$STATE_DIR" "$PANEL_DIR" "$MIRROR_DIR"
		has userdel && { act userdel veilway 2>/dev/null || true; act userdel veilway-panel 2>/dev/null || true; act userdel veilway-xray 2>/dev/null || true; act userdel veilway-mirror 2>/dev/null || true; }
		has deluser && ! has userdel && { act deluser veilway 2>/dev/null || true; act deluser veilway-panel 2>/dev/null || true; act deluser veilway-xray 2>/dev/null || true; act deluser veilway-mirror 2>/dev/null || true; }
	else info "config and data kept"; fi
	act rm -rf "$UPDATE_DIR"
	# The script and its state stay while the web server setup does, since only they can remove that setup.
	if [ -f "$WEB_STATE" ]; then act rm -f "$VER_DIR"/*.version; info "the web server setup stays, and so does $SELF: remove both with: sudo bash $SELF uninstall web, then sudo rm -r $SELF $VER_DIR"
	else act rm -rf "$VER_DIR" "$SELF"; fi
	step "uninstalled. Backups are in $BACKUP_DIR"
}

do_version() {
	local n p
	n="$([ -x "$BIN_DIR/veilway" ] && installed_version node || echo "not installed")"
	p="$([ -x "$BIN_DIR/veilway-panel" ] && installed_version panel || echo "not installed")"
	row "installer" "$SCRIPT_VERSION"
	row "node" "$n"
	row "panel" "$p"
}

# Runs one action of the menu in a subshell, so a die or a Ctrl-C ends the action and not the menu. Exit code 99 means the action only went back, and 130 a Ctrl-C.
menu_run() {
	local rc
	printf '%s' "$CLS"
	[ "$1" = do_status ] || header
	trap ':' INT
	set +e
	( set -e; trap cleanup EXIT; trap 'printf "\n"; exit 130' INT TERM; "$@" )
	rc=$?
	set -e
	trap 'printf "\n"; exit 130' INT TERM
	MENU_RC=$rc
	[ "$rc" = 99 ] || [ "$rc" = 130 ] || { printf '\n'; ask "Press Enter to go back." "" >/dev/null; }
}

menu() {
	local c it=() p ok unit v s dot txt line lines=() extra prefix host port w when f cols=80 ad
	if [ "$ASSUME_YES" = 1 ] || [ "$DRY" = 1 ]; then header; return 0; fi
	MENU=1
	if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ]; then CLS=$'\033[H\033[2J'; read -r _ cols < <(stty size </dev/tty 2>/dev/null) || true; fi
	[[ "$cols" =~ ^[0-9]+$ ]] || cols=80
	while true; do
		printf '%s' "$CLS"
		printf '  %sVeilway%s %sinstaller %s%s\n  %s%s%s\n' "$B" "$Z" "$D" "$SCRIPT_VERSION" "$Z" "$D" "$(rule 40)" "$Z"
		lines=()
		for p in node panel mirror xray; do
			case "$p" in
				node) ok=0; [ -x "$BIN_DIR/veilway" ] && ok=1; unit=veilway.service; v="$(installed_version node)" ;;
				panel) ok=0; [ -x "$BIN_DIR/veilway-panel" ] && ok=1; unit=veilway-panel.service; v="$(installed_version panel)" ;;
				mirror) ok=0; [ -f "$UNIT_DIR/veilway-mirror.service" ] && ok=1; unit=veilway-mirror.service; v="$(installed_version node)" ;;
				xray) ok=0; [ -x "$ADDON_DIR/xray/xray" ] && ok=1; unit=veilway-xray.socket; v="$(cat "$ADDON_DIR/xray/release" 2>/dev/null || true)" ;;
			esac
			if [ "$ok" = 0 ]; then
				[ "$p" = node ] || [ "$p" = panel ] || continue
				dot="$D"; txt="not installed"; v=""
			else
				s=""; has_systemd && s="$(systemctl is-active "$unit" 2>/dev/null || true)"
				case "$s" in active) dot="$G"; txt="running" ;; failed) dot="$R"; txt="failed" ;; "") dot="$D"; txt="no systemd" ;; *) dot="$D"; txt="stopped" ;; esac
			fi
			line="$(printf '  %-6s %-14s %s%s%s %-11s' "$p" "$v" "$dot" "$LED" "$Z" "$txt")"
			if [ "$p" = panel ] && [ "$ok" = 1 ] && [ -r "$CONF_DIR/panel.json" ]; then
				prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
				if [ "$(web_state mode)" = domain ]; then
					host="$(web_state domain)"; port="$(web_state https_port)"
					[ -z "$port" ] || [ "$port" = 443 ] || host="$host:$port"
					extra="https://$host$prefix/"
				else extra="through an SSH tunnel to 127.0.0.1:$PANEL_PORT"; fi
				[ "${#extra}" -le $((cols - 40)) ] || extra="${extra:0:$((cols > 53 ? cols - 43 : 10))}..."
				line+=" ${D}${extra}${Z}"
			fi
			lines+=("$line")
		done
		w="$(web_state web)"
		if [ -z "$w" ]; then txt="none"
		else
			host="$(web_state domain)"; [ "$(web_state mode)" != ip ] || host="$(web_state ip)"
			port="$(web_state https_port)"
			txt="$host:${port:-443}"
		fi
		lines+=("$(printf '  %-6s %-14s %s' web "${w:-none}" "$([ -z "$w" ] || echo "$txt")")")
		f="$VER_DIR/update.check"
		if [ -f "$f" ] && [ ! -L "$f" ]; then
			read -r c <"$f" || true
			when="$(date -r "$f" +%F 2>/dev/null || true)"
			if [[ "$c" =~ $TAG_RE ]] && [ "$c" != none ]; then lines+=("$(printf '  %-6s %s%s waiting%s' update "$Y" "$c" "$Z")")
			else lines+=("$(printf '  %-6s none waiting, checked %s' update "$when")"); fi
		fi
		printf '%s\n' "${lines[@]}"
		printf '\n'
		pick $((3 + ${#lines[@]})) quit "=Set up" "install|Install or add a part" "web|Web server" "addon|Add-ons" "=Daily" "status|Status" "logs|Logs" "restart|Restart" "=Safety" "update|Update" "backup|Backup" "restore|Restore" "=Fix" "check|Check config" "doctor|Doctor" "admin|Admins" "=Remove" "uninstall|Uninstall" || { printf '\n'; return 0; }
		case "$PICKED" in
			install) menu_run do_install "" ;;
			web) menu_run do_web ;;
			addon)
				printf '%s' "$CLS"; header
				do_addon xray status
				printf '\n'
				if [ -x "$ADDON_DIR/xray/xray" ]; then it=("remove|Remove the Xray add-on"); else it=("install|Install the Xray add-on"); fi
				if pick 6 leave "${it[@]}" "leave|Leave it as it is" && [ "$PICKED" != leave ]; then menu_run do_addon xray "$PICKED"; fi
				;;
			status) menu_run do_status ;;
			logs | restart)
				c="$PICKED"; it=()
				[ -x "$BIN_DIR/veilway" ] && it+=("node|Node")
				[ -x "$BIN_DIR/veilway-panel" ] && it+=("panel|Panel")
				[ -f "$UNIT_DIR/veilway-mirror.service" ] && it+=("mirror|Mirror")
				[ "$c" = logs ] || { [ -x "$BIN_DIR/veilway" ] && [ -x "$BIN_DIR/veilway-panel" ] && it+=("both|Node and panel"); }
				if [ "${#it[@]}" = 0 ]; then menu_run warn "no part is installed here"
				else
					printf '%s' "$CLS"; header
					printf '  %s\n\n' "$([ "$c" = logs ] && echo "Logs of which part?" || echo "Restart which part?")"
					if pick 6 back "${it[@]}"; then menu_run "do_$c" "$PICKED"; fi
				fi
				;;
			update)
				menu_run do_update both
				[ "$MENU_RC" != 0 ] || { install -d -m 0755 "$VER_DIR" && printf 'none\n' >"$VER_DIR/update.check"; } || true
				;;
			backup) menu_run do_backup ;;
			restore)
				it=()
				while IFS= read -r f; do
					[ -f "$BACKUP_DIR/$f" ] || continue
					case "$f" in *"|"*) ;; *) it+=("$BACKUP_DIR/$f|$f  ($(date -r "$BACKUP_DIR/$f" "+%F %H:%M" 2>/dev/null || true))") ;; esac
				done < <(ls -1t "$BACKUP_DIR" 2>/dev/null || true)
				it+=("path|Type a path to a backup file")
				printf '%s' "$CLS"; header
				printf '  Restore from which backup? Newest first.\n\n'
				if pick 6 back "${it[@]}"; then
					c="$PICKED"
					[ "$c" != path ] || c="$(ask "Backup file:" "")"
					menu_run do_restore "$c"
				fi
				;;
			check) menu_run run_check ;;
			doctor) menu_run do_doctor ;;
			admin)
				it=()
				if [ -x "$BIN_DIR/veilway-panel" ] && [ -f "$CONF_DIR/panel.json" ]; then
					while IFS= read -r ad; do [ -z "$ad" ] || it+=("${ad%% *}|$ad"); done < <(as_panel_user "$BIN_DIR/veilway-panel" admins --config "$CONF_DIR/panel.json" 2>/dev/null || true)
				fi
				if [ "${#it[@]}" = 0 ]; then menu_run do_admin list
				else
					printf '%s' "$CLS"; header
					printf '  Give which admin a new password?\n\n'
					if pick 6 back "${it[@]}"; then menu_run do_admin reset "$PICKED"; fi
				fi
				;;
			uninstall) menu_run do_uninstall ;;
		esac
	done
}

# The menu's Web server entry: what is set up now and what can be done with it. Code 99 means back.
do_web() {
	local web mode host port site routes on inc ed code url sub prefix it=() args=()
	web="$(web_state web)"; mode="$(web_state mode)"
	if [ -z "$web" ]; then row "web server" "none set up by this script"
	else
		host="$(web_state domain)"; [ "$mode" != ip ] || host="$(web_state ip)"
		port="$(web_state https_port)"; port="${port:-443}"
		site="$CADDY_SITE"; routes="$CADDY_ROUTES"
		[ "$web" = caddy ] || { site="$NGINX_SITE"; routes="$NGINX_ROUTES"; }
		on=unknown
		if has ss; then on=off; [ -z "$(ss -H -ltn "sport = :$DECOY_PORT" 2>/dev/null)" ] || on=on; fi
		inc=no; grep -qF "$routes/" "$site" 2>/dev/null && inc=yes
		row "web server" "$web"
		row "address" "$host:$port ($([ "$mode" = ip ] && echo "IP, self-signed" || echo domain))"
		row "site file" "$site$([ -f "$site" ] || echo " (missing)")"
		row "plain site" "$on$([ "$on" != on ] || echo ", on 127.0.0.1:$DECOY_PORT only, page $WEB_ROOT/index.html")"
		row "routes include" "$inc"
	fi
	printf '\n'
	if [ -z "$web" ]; then it=("set|Set up a web server for the panel"); else it=("check|Check it" "decoy|Edit the plain page" "remove|Remove it"); fi
	pick 11 back "${it[@]}" "back|Back" || return 99
	case "$PICKED" in
		back) return 99 ;;
		set)
			[ -f "$CONF_DIR/panel.json" ] || die "the panel is not installed here: use Install or add a part first"
			need_root
			refuse_links
			detect_target
			ensure_tools
			pick 11 back "domain|I have a domain name that points at this server" "ip|No domain: use this server's IP, with a self-signed certificate" || return 99
			if [ "$PICKED" = domain ]; then WEB_NOW=1; else NO_DOMAIN=1; fi
			web_plan panel
			[ -n "$DOMAIN" ] || [ "$NO_DOMAIN" = 1 ] || die "no web server was set up"
			TMP="$(mktemp -d)"
			web_setup
			svc restart veilway-panel.service
			prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
			sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
			if [ "$NO_DOMAIN" = 1 ]; then box "Web server" "Subscriptions: https://$HTTPS_HOST$sub/main, self-signed, pin $(web_state pin)" "Admin pages: ssh -L 8480:127.0.0.1:$PANEL_PORT root@$PUBLIC_IP, then http://localhost:8480$prefix/"
			else box "Web server" "Admin pages: https://$HTTPS_HOST$prefix/" "Port 80 must stay reachable: the certificate is checked over it."; fi
			;;
		check)
			if ! has "$web"; then warn "$web is not installed here"
			elif [ "$web" = caddy ]; then caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 && step "caddy accepts its config" || warn "caddy refuses its config: run caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile"
			else nginx -t >/dev/null 2>&1 && step "nginx accepts its config" || warn "nginx refuses its config: run nginx -t"; fi
			systemctl is-active --quiet "$web.service" 2>/dev/null && step "$web is running" || warn "$web is not running: sudo systemctl start $web"
			url="https://$host:$port/"
			if [ "$mode" = ip ]; then url="https://127.0.0.1:$port/"; else args=(--resolve "$host:$port:127.0.0.1"); fi
			code="$(curl -ksS -o /dev/null -m 8 -w '%{http_code}' ${args[@]+"${args[@]}"} "$url" 2>/dev/null || true)"
			if [ "${code:-000}" != 000 ]; then step "$url answers $code"; else warn "$url gave no answer from this server: the web server may not listen there"; fi
			code="$(curl -sS -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$DECOY_PORT/" 2>/dev/null || true)"
			if [ "${code:-000}" != 000 ]; then step "the plain site on 127.0.0.1:$DECOY_PORT answers $code"; else warn "nothing answers on 127.0.0.1:$DECOY_PORT: a node's decoy origin needs a page there"; fi
			;;
		decoy)
			info "the plain page is $WEB_ROOT/index.html"
			info "a guide for a good one: https://veilway-project.github.io/veilway-docs/guides/decoy-site/"
			ed="${EDITOR:-nano}"; has "$ed" || ed=vi
			if [ ! -f "$WEB_ROOT/index.html" ]; then warn "there is no page at $WEB_ROOT/index.html"
			elif has "$ed" && confirm "Open it in $ed now?"; then "$ed" "$WEB_ROOT/index.html" </dev/tty >/dev/tty || true; fi
			;;
		remove) do_uninstall_web ;;
	esac
}

# SHA-256 of the archives of the one Xray-core release this Veilway runs, from the .dgst files the release publishes. Nothing else is trusted: an archive that does not match is refused, and the node checks the executable inside against its own pin before every start.
xray_pin() {
	case "$1" in
		linux-64) printf '%s' 0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978 ;;
		linux-arm64-v8a) printf '%s' d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c ;;
	esac
}

# The add-on lives in a folder only root can write, so the node, which runs the executable, can never replace it.
do_addon() {
	local name="${1:-}" action="${2:-install}" arch pin got
	[ "$name" = xray ] || die "the only add-on is xray: try addon xray install, remove or status"
	case "$action" in
		install)
			need_root
			refuse_links
			detect_target
			ensure_tools
			has unzip || { info "installing unzip"; pkg_install unzip || die "install unzip with your package manager and run this again"; }
			case "$TARGET" in x86_64*) arch=linux-64 ;; *) arch=linux-arm64-v8a ;; esac
			pin="$(xray_pin "$arch")"
			if [ "$DRY" = 1 ]; then
				dry "download Xray-core $XRAY_RELEASE (Xray-$arch.zip) from $RELEASE_BASE/XTLS/Xray-core"
				dry "refuse unless its SHA-256 is $pin"
				dry "install the executable into $ADDON_DIR/xray, owned by root, the units that run it under the user veilway-xray, and let the user veilway into its group for the sockets of Xray outbounds"
				return 0
			fi
			TMP="$(mktemp -d)"
			fetch "$RELEASE_BASE/XTLS/Xray-core/releases/download/$XRAY_RELEASE/Xray-$arch.zip" "$TMP/xray.zip" "downloading Xray-core $XRAY_RELEASE"
			got="$(sha256sum "$TMP/xray.zip" | cut -d' ' -f1)"
			[ "$got" = "$pin" ] || die "the archive's SHA-256 is $got, not the pinned $pin: refusing"
			step "the archive matches the pinned SHA-256"
			unzip -p "$TMP/xray.zip" xray >"$TMP/xray" || die "the archive has no xray executable"
			ensure_user veilway-xray /nonexistent
			install -d -m 0755 -o root -g root "$ADDON_DIR" "$ADDON_DIR/xray"
			install -m 0755 -o root -g root "$TMP/xray" "$ADDON_DIR/xray/xray.new"
			mv -f "$ADDON_DIR/xray/xray.new" "$ADDON_DIR/xray/xray"
			printf '%s\n' "$XRAY_RELEASE" >"$ADDON_DIR/xray/release"
			step "installed Xray-core $XRAY_RELEASE in $ADDON_DIR/xray"
			xray_units
			xray_node_group
			daemon_reload
			svc enable veilway-xray.socket
			svc restart veilway-xray.socket
			# The node joins the group of Xray's user when it starts, so a node that runs is started again for it.
			[ -f "$UNIT_DIR/veilway.service" ] && svc restart veilway.service
			info "the node starts it when its config has an xray inbound; create one in the panel"
			;;
		remove)
			need_root
			svc stop veilway-xray.socket || true; svc stop veilway-xray.service || true
			svc disable veilway-xray.socket || true
			act rm -f "$UNIT_DIR/veilway-xray.socket" "$UNIT_DIR/veilway-xray.service"
			if has gpasswd; then act gpasswd -d veilway veilway-xray >/dev/null 2>&1 || true; else act deluser veilway veilway-xray >/dev/null 2>&1 || true; fi
			act rm -rf "$ADDON_DIR/xray"
			daemon_reload
			has_systemd && systemctl is-active --quiet veilway.service && svc restart veilway.service || true
			step "removed the xray add-on; the node stops it on its restart"
			;;
		status)
			if [ -x "$ADDON_DIR/xray/xray" ]; then row "xray" "installed ($XRAY_RELEASE pinned, $(sha256sum "$ADDON_DIR/xray/xray" | cut -c1-16)...), host $(unit_state veilway-xray.socket)"; else row "xray" "not installed"; fi
			;;
		*) die "unknown action \"$action\": try install, remove or status" ;;
	esac
}

# One nftables table of its own forwards the chosen ports to the node and masquerades the return path, and limits new connections and concurrent TCP connections per source. The state file keeps what was there before, so uninstall relay removes exactly what this added.
do_install_relay() {
	local node="" rate=50 conns=256 transports=() names="" ports="" nat="" addr="" address="" name lp np proto busy t
	local added_pkg=0 added_svc=0 prev="" inc
	local -A seen=()
	need_root
	has apt-get || die "the relay installer runs on Debian or Ubuntu: it needs apt-get"
	while [ $# -gt 0 ]; do
		case "$1" in
			--transport) [ $# -gt 1 ] || die "--transport needs a value, for example tls:443"; transports+=("$2"); shift ;;
			--transport=*) transports+=("${1#*=}") ;;
			--rate) [ $# -gt 1 ] || die "--rate needs a number"; rate="$2"; shift ;;
			--conns) [ $# -gt 1 ] || die "--conns needs a number"; conns="$2"; shift ;;
			-*) die "unknown option \"$1\" for install relay" ;;
			*) [ -z "$node" ] || die "give one node address, not \"$node\" and \"$1\""; node="$1" ;;
		esac
		shift
	done
	[ -n "$node" ] || die "usage: veilway.sh install relay <node-ip> [--transport tls:443 ...] [--rate 50] [--conns 256]"
	[[ "$node" =~ $IPV4_RE ]] || die "the node must be an IPv4 address, not \"$node\": give its IP, the relay does not resolve names"
	case "$node" in 0.* | 127.* | 169.254.* | 22[4-9].* | 23[0-9].* | 2[45][0-9].*) die "$node is not an address a relay can forward to" ;; esac
	[[ "$node" =~ $PRIVATE_RE ]] && ! ip -4 -o route show to match "$node" | grep -qv "^default " && die "$node is private and this server has no route to it: the relay could not reach it"
	ip -4 -o addr show | grep -q " $node/" && die "$node is this server's own address: a relay cannot forward to itself"
	[[ "$rate" =~ $NUM_RE ]] || die "--rate is new connections per source per second: a number from 1 up"
	[[ "$conns" =~ $NUM_RE ]] || die "--conns is TCP connections per source at once: a number from 1 up"
	[ "${#transports[@]}" -gt 0 ] || { [ "$ASSUME_YES" = 1 ] && die "pass --transport name:port, for example --transport tls:443"; read -r -a transports <<<"$(ask "Transports to relay as name:port, separated by spaces (udp, udp-obfs, tls, ws) [tls:443]" tls:443)" || true; }
	[ "${#transports[@]}" -gt 0 ] || die "no transport given"
	for t in "${transports[@]}"; do
		IFS=: read -r name lp np <<<"$t"
		np="${np:-$lp}"
		case "$name" in
			udp | udp-obfs) proto=udp ;;
			tls | ws) proto=tcp ;;
			fronted) die "fronted goes through a content delivery network, not a relay: its edge address goes in the panel" ;;
			*) die "unknown transport \"$name\": use udp, udp-obfs, tls or ws" ;;
		esac
		[[ "$lp" =~ $NUM_RE && "$lp" -le 65535 && "$np" =~ $NUM_RE && "$np" -le 65535 ]] || die "$t: the ports must be numbers from 1 to 65535"
		[ -z "${seen[$proto:$lp]:-}" ] || die "two transports listen on $proto port $lp"
		seen[$proto:$lp]=1
		if [ "$proto" = tcp ]; then busy="$(ss -H -ltn "sport = :$lp")"; else busy="$(ss -H -lun "sport = :$lp")"; fi
		[ -z "$busy" ] || die "$proto port $lp is already in use here, and the relay would take that traffic"
		printf -v nat '%s\t\tmeta nfproto ipv4 %s dport %s dnat ip to %s:%s\n' "$nat" "$proto" "$lp" "$node" "$np"
		names+="${names:+, }$name"
		ports+="${ports:+, }$name $lp"
		[ "$np" = "$lp" ] || ports+=" (node port $np)"
	done
	[[ "$names" == *udp* && ( "$names" == *tls* || "$names" == *ws* ) ]] && warn "udp and tls on one address make apps rate tls Detectable: give them a second relay for tls"
	if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then warn "ufw is active and drops forwarded traffic by default: set DEFAULT_FORWARD_POLICY=\"ACCEPT\" in /etc/default/ufw and reload it"; fi
	addr="$(ip -4 -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' || true)"
	address="$addr"
	if [ -z "$addr" ] || [[ "$addr" =~ $PRIVATE_RE ]]; then address="your public IPv4 from your provider (this server's own address is ${addr:-none})"; fi
	has nft || added_pkg=1
	has_systemd && [ "$(systemctl is-enabled nftables.service 2>/dev/null)" != enabled ] && added_svc=1
	prev="$(sysctl -n net.ipv4.ip_forward)"
	if [ -f "$RELAY_STATE" ]; then info "kept $RELAY_STATE: the state from the first install relay"
	elif [ "$DRY" = 1 ]; then dry "record in $RELAY_STATE what was there before: nftables added $added_pkg, nftables.service enabled $added_svc, ip_forward $prev"
	else install -d -m 0755 "$VER_DIR"; printf 'nftables_installed=%s\nnftables_enabled=%s\nip_forward=%s\n' "$added_pkg" "$added_svc" "$prev" >"$RELAY_STATE"; fi
	has nft || pkg_install nftables || die "cannot install nftables: install it with apt-get and run this again"
	act install -d -m 0755 /etc/nftables.d
	svc enable nftables.service
	write_unit "$SYSCTL_RELAY" <<EOF
net.ipv4.ip_forward = 1
EOF
	act sysctl -q -w net.ipv4.ip_forward=1
	write_unit "$NFT_RELAY" <<EOF
# Owned by veilway.sh install relay. The add and delete lines make a reload replace this table alone.
add table inet veilway_relay
delete table inet veilway_relay
table inet veilway_relay {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
$nat	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ct status dnat ip daddr $node masquerade
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip daddr $node ct state new meter veilway_relay_new size 65536 { ip saddr timeout 60s limit rate over $rate/second } counter drop
		ip daddr $node meta l4proto tcp ct state new ct count over $conns counter drop
	}
}
EOF
	act nft -f "$NFT_RELAY" || { rm -f -- "$NFT_RELAY"; die "nftables rejected the relay rules: nothing was loaded"; }
	inc="include \"$NFT_RELAY\""
	if [ "$DRY" = 1 ]; then dry "add $inc to $NFT_CONF, so nftables.service loads the table at boot"
	elif ! grep -qxF "$inc" "$NFT_CONF"; then printf '%s\n' "$inc" >>"$NFT_CONF"; fi
	[ "$DRY" = 1 ] || step "relay table loaded from $NFT_RELAY"
	info "limits per source: $rate new connections a second, $conns TCP connections at once"
	box "Relay" \
		"In the panel, under Settings > Relays, add a relay with:" \
		"  name        any, for example relay-1" \
		"  address     $address" \
		"  transports  $names" \
		"  ports       $ports" \
		"  inbounds    the ones that serve these transports" \
		"The panel needs a port only where the relay's differs from the node's." \
		"Save, then publish the profiles again on Profiles."
	[ "$DRY" = 1 ] || step "done. Remove it with: sudo bash veilway.sh uninstall relay"
}

# Removes what install relay added: the table, the files it wrote, its include line, and the settings recorded in its state file.
do_uninstall_relay() {
	local was_pkg was_svc was_fwd
	need_root
	[ -f "$NFT_RELAY" ] || [ -f "$RELAY_STATE" ] || die "no relay is installed here"
	confirm "Remove the relay table and the files install relay wrote, and undo what it added to nftables and IP forwarding?" || die "cancelled"
	was_pkg="$(sed -n 's/^nftables_installed=//p' "$RELAY_STATE" 2>/dev/null || true)"
	was_svc="$(sed -n 's/^nftables_enabled=//p' "$RELAY_STATE" 2>/dev/null || true)"
	was_fwd="$(sed -n 's/^ip_forward=//p' "$RELAY_STATE" 2>/dev/null || true)"
	if nft list table inet veilway_relay >/dev/null 2>&1; then act nft delete table inet veilway_relay; fi
	act rm -f -- "$NFT_RELAY" "$SYSCTL_RELAY"
	act rmdir /etc/nftables.d 2>/dev/null || true
	[ -f "$NFT_CONF" ] && act sed -i "\#^include \"$NFT_RELAY\"\$#d" "$NFT_CONF"
	if [ "${was_fwd:-1}" = 0 ]; then act sysctl -q -w net.ipv4.ip_forward=0; fi
	if [ "${was_svc:-0}" = 1 ]; then svc disable nftables.service; fi
	if [ "${was_pkg:-0}" = 1 ]; then act env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 remove -y -qq nftables; fi
	act rm -f -- "$RELAY_STATE"
	[ "$DRY" = 1 ] || step "relay removed: its table, files and the settings it added"
}

# Copies a release of the node and of the panel, and the signed pointers, into a folder laid out as GitHub does, to serve with any web server or to carry. Everything is verified before it is stored. Needs no root.
do_mirror_sync() {
	local out="${1:-}" repo key product tag ptag list n dest ptr cur names=() stored=0
	[ -n "$out" ] || die "usage: veilway.sh mirror-sync <folder> [--version vX.Y.Z]"
	ensure_tools download
	if [ "$DRY" = 1 ]; then
		dry "for the node and the panel: read the signed pointer, list the release's files, download each with its .minisig and verify it"
		dry "store them under $out/<owner>/<repo>/releases/download/<tag>/, the pointers under releases/latest/download/ and at the top, and veilway.sh at the top"
		return 0
	fi
	TMP="$(mktemp -d)"
	install -d -m 0755 "$out"
	for product in veilway veilway-panel; do
		if [ "$product" = veilway ]; then repo="$CORE_REPO"; key="$NODE_PUBKEY"; else repo="$PANEL_REPO"; key="$PANEL_PUBKEY"; fi
		ptag=""
		if pointer_tag "$repo" "$key" "$product"; then ptag="$TAG_OUT"; fi
		tag="${WANT_VERSION:-$ptag}"
		if [ -z "$tag" ]; then
			[ "$MIRROR_ONLY" = 0 ] || die "no mirror has a signed latest pointer for $product: pass --version <tag>"
			tag="$(latest_tag "$repo")"
		fi
		names=()
		list=""
		if [ "$MIRROR_ONLY" = 0 ] && [ "$RELEASE_BASE" = https://github.com ]; then
			list="$(curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 "https://api.github.com/repos/$repo/releases/tags/$tag" 2>/dev/null | sed -n 's/.*"browser_download_url": *"[^"]*\/\([^"\/]*\)".*/\1/p' || true)"
		fi
		if [ -n "$list" ]; then
			while read -r n; do
				[[ "$n" =~ ^[A-Za-z0-9._+-]+$ && "$n" != *.minisig ]] || continue
				if grep -qxF "$n.minisig" <<<"$list"; then names+=("$n"); else info "$n has no signature and is not copied"; fi
			done <<<"$list"
			[ "${#names[@]}" -gt 0 ] || { warn "$product has no signed files for $tag: skipped"; continue; }
		else
			info "the list of $product $tag could not be read, so only the files the installer needs are copied"
			if [ "$product" = veilway ]; then names=(veilway-x86_64-unknown-linux-musl veilway-aarch64-unknown-linux-musl veilway.sh)
			else names=(veilway-panel-x86_64-unknown-linux-musl veilway-panel-aarch64-unknown-linux-musl); fi
		fi
		dest="$out/$repo/releases/download/$tag"
		install -d -m 0755 "$dest"
		for n in "${names[@]}"; do
			download_verified "$repo" "$key" "$n" "$tag" "$product"
			mv -f "$TMP/$n" "$dest/$n.new"; chmod 0644 "$dest/$n.new"; mv -f "$dest/$n.new" "$dest/$n"
			mv -f "$TMP/$n.minisig" "$dest/$n.minisig.new"; chmod 0644 "$dest/$n.minisig.new"; mv -f "$dest/$n.minisig.new" "$dest/$n.minisig"
			stored=$((stored + 1))
		done
		step "$product $tag: ${#names[@]} files in $dest"
		if [ "$ptag" != "$tag" ]; then info "no pointer written: the signed latest of $product is ${ptag:-unknown}, not $tag"; continue; fi
		ptr="$out/$repo/releases/latest/download"
		cur="$(sed -n "s/^$product //p" "$ptr/latest-$product.txt" 2>/dev/null | head -n 1 || true)"
		if [ -n "$cur" ] && [[ "$cur" =~ $TAG_RE ]] && semver_lower "$tag" "$cur"; then warn "kept the pointer in $out, which names the newer $cur"; continue; fi
		install -d -m 0755 "$ptr"
		for n in "$ptr" "$out"; do
			install -m 0644 "$TMP/latest-$product.txt" "$n/latest-$product.txt.new"; mv -f "$n/latest-$product.txt.new" "$n/latest-$product.txt"
			install -m 0644 "$TMP/latest-$product.txt.minisig" "$n/latest-$product.txt.minisig.new"; mv -f "$n/latest-$product.txt.minisig.new" "$n/latest-$product.txt.minisig"
		done
		step "pointer latest-$product.txt says $tag"
		if [ "$product" = veilway ] && [ -f "$dest/veilway.sh" ]; then
			install -m 0644 "$dest/veilway.sh" "$out/veilway.sh"; install -m 0644 "$dest/veilway.sh.minisig" "$out/veilway.sh.minisig"
			step "veilway.sh of $tag is at the top of $out"
		fi
	done
	step "done: $stored files in $out. Serve the folder over https, then install with --mirror https://your-host"
}

# True for a package that dpkg has installed (not one with only its config files left).
pkg_has() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }

# What the web server setup added, one key=value per line, so uninstall web takes back exactly that.
web_note() {
	[ "$DRY" = 1 ] && return 0
	install -d -m 0755 "$VER_DIR"
	sed -i "/^$1=/d" "$WEB_STATE" 2>/dev/null || true
	printf '%s=%s\n' "$1" "$2" >>"$WEB_STATE"
}

web_state() { sed -n "s/^$1=//p" "$WEB_STATE" 2>/dev/null | head -n 1 || true; }

# Installs the packages that are missing and records them, so uninstall web removes only these.
web_pkg() {
	local p new=()
	for p in "$@"; do pkg_has "$p" || new+=("$p"); done
	[ "${#new[@]}" -gt 0 ] || return 0
	pkg_install "${new[@]}" || die "cannot install ${new[*]}: install it with apt-get and run this again"
	web_note pkgs "$(web_state pkgs) ${new[*]}"
}

# Run before anything is installed: finds out what already holds ports 80 and the HTTPS port and stops with an explanation when the setup would take them from someone. The node on the HTTPS port is the one case it works around, see web_free_https.
web_preflight() {
	local s p out held="" other="" same=0 ports=(80 "$HTTPS_PORT")
	# Caddy also opens port 80 in no-domain mode, to answer it with 404 instead of a redirect.
	[ "$NO_DOMAIN" = 0 ] || [ "$WEB" = caddy ] || ports=("$HTTPS_PORT")
	has ss || pkg_install iproute2 || die "cannot install iproute2, which shows what holds ports ${ports[*]}"
	has apt-get || die "the automatic web server setup runs on Debian or Ubuntu: it needs apt-get. Install a web server by hand with the snippets that the install prints, or run this without --domain."
	for s in nginx caddy apache2 httpd lighttpd haproxy; do
		if ! has_systemd || ! systemctl is-active --quiet "$s.service" 2>/dev/null; then continue; fi
		if [ "$s" = "$WEB" ]; then same=1; else other+="${other:+, }$s"; fi
	done
	for p in "${ports[@]}"; do
		out="$(ss -H -ltnp "sport = :$p" 2>/dev/null || true)"
		[ -n "$out" ] || continue
		if [ "$p" = "$HTTPS_PORT" ] && grep -q '"veilway"' <<<"$out"; then NODE_HTTPS=1
		elif ! grep -q "\"$WEB\"" <<<"$out"; then held+="${held:+, }$p"; fi
	done
	if [ -n "$other" ] || [ -n "$held" ]; then
		box "A web server is already here" \
			"${other:+Running: $other}" \
			"${held:+TCP port(s) in use by something else: $held}" \
			"Two programs cannot share ports ${ports[*]}, and this script will not stop" \
			"or replace a server it did not install. Either add the panel to your own" \
			"server by hand (run without --domain for the snippets), or stop that server" \
			"and run this again."
		die "nothing was installed or changed"
	fi
	if [ "$same" = 1 ]; then
		warn "$WEB already runs here. Your own configuration stays as it is: this only adds the panel's site file$([ "$WEB" = caddy ] && echo " and one import line")."
		confirm "Add the panel's site to the running $WEB?" || die "cancelled, nothing was changed"
	fi
	if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then warn "ufw is active: allow ports ${ports[*]// /,} (sudo ufw allow ${ports[*]// /,}/tcp) or the site cannot be reached"; fi
	[ "$NO_DOMAIN" = 1 ] || getent hosts "$DOMAIN" >/dev/null 2>&1 || warn "$DOMAIN does not resolve yet: the certificate needs its DNS record to point at this server"
	return 0
}

# The node may keep a TCP transport on the HTTPS port for its users, and the web server needs that port for HTTPS. The safe default: the web server takes the port and the node's TCP transports on it move to 8443 (8444 when the port is 8443). The node cannot share the port with the web server without reading the web server's certificate files, which its sandbox and their owner both forbid, so that design was not built. Profiles that name the port stop working until they are published again in the panel.
web_free_https() {
	# shellcheck disable=SC2016
	local f="$NODE_DIR/config.json" old new move_to=8443 sel='(.inbounds[]?.transports[]? | select((.type | IN("udp", "udp-obfs") | not) and ((.listen // "") | endswith($p))))'
	[ "$HTTPS_PORT" != 8443 ] || move_to=8444
	if [ "$DRY" = 1 ]; then dry "if the node listens on TCP $HTTPS_PORT: move its transports there to $move_to in $f, check the config and restart the node"; return 0; fi
	[ "$NODE_HTTPS" = 1 ] || return 0
	web_pkg jq
	old="$(as_node_user cat "$f")" || die "cannot read $f"
	[ "$(jq --arg p ":$HTTPS_PORT" "[$sel] | length" <<<"$old")" -gt 0 ] || die "the node listens on $HTTPS_PORT with something this script cannot move: move it by hand, then run this again. Nothing was changed."
	[ -z "$(ss -H -ltn "sport = :$move_to")" ] || die "port $move_to is in use here, so the node's transport cannot move there: free it or move the transport by hand. Nothing was changed."
	warn "the node's transport on $HTTPS_PORT has to move: the web server needs $HTTPS_PORT for HTTPS"
	confirm "Move the node's TCP transports from port $HTTPS_PORT to $move_to? Profiles that name $HTTPS_PORT stop working until you publish them again in the panel." || die "cancelled, nothing was changed"
	new="$(jq --arg p ":$HTTPS_PORT" --arg m ":$move_to" "($sel | .listen) |= (rtrimstr(\$p) + \$m)" <<<"$old")"
	backup_file "$f"
	( umask 077; printf '%s\n' "$new" | as_node_user tee "$f.new" >/dev/null )
	as_node_user mv -f "$f.new" "$f"
	as_node_user chmod 0600 "$f"
	if ! run_check; then
		printf '%s\n' "$old" | as_node_user tee "$f" >/dev/null
		die "the node's config did not pass its check with $move_to, so the old one is back"
	fi
	svc restart veilway.service
	sleep 2
	if [ -n "$(ss -H -ltnp "sport = :$HTTPS_PORT" | grep '"veilway"' || true)" ]; then
		printf '%s\n' "$old" | as_node_user tee "$f" >/dev/null
		svc restart veilway.service
		die "the node still holds $HTTPS_PORT after the move, so its old config is back. Move its listener by hand."
	fi
	web_note node_moved "$HTTPS_PORT $move_to"
	step "moved the node's TCP transports from $HTTPS_PORT to $move_to"
	warn "profiles that name port $HTTPS_PORT stop working until you press Publish in the panel's Profiles page (the node's TCP transports are on $move_to now)"
}

# Written once and never over an edit: the operator owns the page. Each server draws its own from these parts (topic, title, entries, dates, type and colors), so no two serve the same text or bytes and a search for one page finds one server. A page of the operator's own is still the better cover.
web_decoy() {
	if [ "$DRY" = 1 ]; then dry "write a plain static page to $WEB_ROOT/index.html if there is none"; return 0; fi
	if [ -e "$WEB_ROOT/index.html" ]; then info "kept existing $WEB_ROOT/index.html"; return 0; fi
	local cls title titles=() tags=() items=() fonts palette pal width size lead i n pick picked=() day body="" tag align foot when
	rnd() { echo $(( $(od -An -N2 -tu2 /dev/urandom) % $1 )); }
	case "$(rnd 6)" in
		0) titles=("Vegetable diary" "Back plot" "Beds and borders"); tags=("Vegetables, weather, and a record of what to do differently." "What grew, what didn't, and what the slugs thought of it.")
			items=("Tomatoes|Planted late and staked badly. They still gave more than the two of us could eat, and the neighbors took the rest." "The compost pile|It works when it is wet and does nothing when it is dry. Grass clippings in thin layers, never a heap." "Watering|A barrel under the gutter covers the beds for most of the summer. A lid keeps the leaves out." "Garlic in October|Planted the cloves from the market, not the ones from the seed catalog. Next summer will tell if that was cheap or clever." "The bean frame|Bamboo and string held up until the first real wind. Rebuilt it lower, which the beans did not seem to mind." "Seed packets|Half the packets in the drawer are older than the drawer. A germination test on a wet towel sorted out which ones still count.") ;;
		1) titles=("Kitchen notebook" "Mostly soup" "What we ate this week"); tags=("Recipes that worked, written down before they are forgotten." "Plain cooking for two, with notes on what to change next time.")
			items=("Lentil soup|Red lentils, one onion, a spoon of cumin and enough water. It is better on the second day, so make twice as much." "Bread that rises|The trick was a warmer kitchen, not more yeast. The oven with only the light on is warm enough." "Using up rice|Day old rice fries better than fresh. A beaten egg and whatever is left in the fridge does the rest." "Pickled onions|Vinegar, sugar, salt, and a jar that has been in hot water. Ready in an hour, gone in two days." "A failed cake|Too much baking soda tastes like a coin. Half a teaspoon would have been plenty." "Tea for guests|A pot of black tea with cardamom pods keeps people at the table longer than any dessert.") ;;
		2) titles=("Trail log" "Weekend walks" "Up the hill"); tags=("Short notes from walks near home, with the bits worth remembering." "Where we went, how long it took, and where the mud was.")
			items=("The ridge path|Two hours up, one and a half down. The last stretch is loose stones, so good shoes matter more than good legs." "Early start|Leaving at six meant the car park was empty and the light was low and gold on the fields." "Lost the trail|The markers stop after the second gate. Following the stream brought us back to the road eventually." "Rain gear|The cheap jacket kept the rain out and the sweat in. Next time, something that breathes." "The lake loop|Flat, short, and full of families on a Sunday. Better on a weekday morning." "Maps|The paper map was right about the bridge being closed. The phone was not.") ;;
		3) titles=("Workbench notes" "Fixing things" "The repair shelf"); tags=("Small repairs around the house and what each one took." "Things that were broken, and some that still are.")
			items=("The dripping tap|A new washer cost almost nothing. Finding the right size took three trips to the hardware shop." "Bike chain|Cleaned and oiled after a winter outside. It still skips in the smallest gear, so a new one is on the list." "A wobbly chair|Wood glue and a clamp overnight. Firm again, as long as nobody leans back." "Old radio|The volume knob crackled. Contact cleaner fixed it in a minute, after an hour of opening the case." "Door that sticks|Planed a few millimeters off the bottom edge. Painted it again so the bare wood does not swell." "Lamp cord|Replaced the frayed cord with a new one and a proper strain relief. It was safer than it looked, but not by much.") ;;
		4) titles=("Reading list" "Books this year" "Shelf notes"); tags=("Short thoughts on what I read, mostly so I remember reading it." "Notes in the margin, collected in one place.")
			items=("Slow start|The first hundred pages were hard going. The rest made up for it, which is not always the case." "A short one|Finished in two evenings. It said what it had to say and stopped, which more books should do." "Library finds|The best book this month came from the returns trolley, not from any list." "Rereading|Picked up a book from school years. It was shorter and funnier than I remembered." "Gave up|Stopped halfway through a long novel. Life is short and the shelf is long." "Notes|Writing two lines after each chapter helped more than underlining ever did.") ;;
		*) titles=("Photo notes" "Contact sheet" "Film and light"); tags=("Notes on pictures taken, the settings, and what I would change." "A place to keep what I learn about taking pictures.")
			items=("Morning fog|Everything looked better at six. By eight the fog had gone and so had the pictures." "One lens|A week with only the old fifty. Walking closer worked better than any zoom." "Windows|Side light from a window beats the flash on the camera every time." "Night street|A high ISO and a steady wall made up for not carrying a tripod." "Printing|Small prints on matte paper look better on the wall than large glossy ones. Hard to say why." "Old film|A roll from a drawer came back with odd colors. Some of them are the best of the year.") ;;
	esac
	fonts=("Georgia, 'Times New Roman', serif" "'Iowan Old Style', Palatino, 'Book Antiqua', serif" "Charter, 'Bitstream Charter', Cambria, serif" "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif" "'Helvetica Neue', Helvetica, Arial, sans-serif" "Verdana, Geneva, sans-serif")
	palette=("#f6f4ee #2b2b26 #7a776b #5b6b3a" "#ffffff #222222 #777777 #2a5d8f" "#fbf8f3 #33302b #8a8378 #8a4b2a" "#f3f5f4 #1f2a27 #6f7d78 #2f6f5e" "#fdfcf8 #2e2a24 #8c8577 #6a4c93" "#f7f7f5 #262626 #737373 #a33b3b")
	read -r -a pal <<<"${palette[$(rnd ${#palette[@]})]}"
	width=$((34 + $(rnd 9))); size=$((16 + $(rnd 3))); lead="1.$((5 + $(rnd 3)))"; align=$([ "$(rnd 3)" = 0 ] && echo center || echo left)
	n=$((3 + $(rnd 3))); day=$((3 + $(rnd 40))); cls=(meta date note small sub when); cls=${cls[$(rnd 6)]}
	while [ "${#picked[@]}" -lt "$n" ]; do pick=$(rnd ${#items[@]}); [[ " ${picked[*]} " == *" $pick "* ]] || picked+=("$pick"); done
	tag=$([ "$(rnd 2)" = 0 ] && echo article || echo section)
	for i in "${picked[@]}"; do
		when="$(date -u -d "-$day days" "+%B %-d, %Y")"; day=$((day + 6 + $(rnd 30)))
		if [ "$(rnd 2)" = 0 ]; then body+="<$tag><h2>${items[$i]%%|*}</h2><p class=\"$cls\">$when</p><p>${items[$i]#*|}</p></$tag>"$'\n'; else body+="<$tag><p class=\"$cls\">$when</p><h2>${items[$i]%%|*}</h2><p>${items[$i]#*|}</p></$tag>"$'\n'; fi
	done
	foot=("Updated when there is something to say." "Written for myself, read by a few." "No comments, but thanks for reading." "More when the weather changes." "Last updated $(date -u -d "-$((3 + $(rnd 20))) days" "+%B %Y").")
	title="${titles[$(rnd ${#titles[@]})]}"
	install -d -m 0755 "$WEB_ROOT"
	cat >"$WEB_ROOT/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
body { font: ${size}px/$lead ${fonts[$(rnd ${#fonts[@]})]}; color: ${pal[1]}; background: ${pal[0]}; margin: 0; }
main { max-width: ${width}rem; margin: 0 auto; padding: $((2 + $(rnd 3)))rem 1.25rem; }
header { text-align: $align; margin-bottom: 2rem; }
h1 { font-size: 1.$((6 + $(rnd 4)))rem; margin: 0 0 .25rem; color: ${pal[3]}; }
h2 { font-size: 1.$((1 + $(rnd 2)))rem; margin: 1.8rem 0 .2rem; }
p { margin: .4rem 0; }
.$cls { color: ${pal[2]}; font-size: .9rem; }
footer { margin-top: 3rem; color: ${pal[2]}; font-size: .85rem; }
</style>
</head>
<body>
<main>
<header><h1>$title</h1><p class="$cls">${tags[$(rnd ${#tags[@]})]}</p></header>
${body}<footer>${foot[$(rnd ${#foot[@]})]}</footer>
</main>
</body>
</html>
EOF
	web_note decoy_sha "$(sha256sum "$WEB_ROOT/index.html" | cut -d' ' -f1)"
	step "wrote the plain site $WEB_ROOT/index.html, drawn for this server"
}

web_caddy() {
	local cf="/etc/caddy/Caddyfile" cand fresh=0 tls="" prefix="$1" sub="$2"
	if ! has caddy && ! pkg_has caddy; then
		fresh=1
		if [ "$DRY" = 1 ]; then dry "install caddy from the system packages if they are 2.6 or newer, else from Caddy's apt repository (signing key from dl.cloudsmith.io)"
		else
			apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null 2>&1 || true
			cand="$(apt-cache policy caddy 2>/dev/null | sed -n 's/^ *Candidate: //p')"
			if [ -z "$cand" ] || [ "$cand" = "(none)" ] || ! dpkg --compare-versions "$cand" ge 2.6; then
				info "the system's caddy is ${cand:-missing} (2.6 is needed): using Caddy's own apt repository"
				web_pkg gnupg ca-certificates curl
				curl -fsSL --proto '=https' --tlsv1.2 https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg || die "cannot get Caddy's signing key"
				printf '%s\n' "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" >/etc/apt/sources.list.d/caddy-stable.list
				web_note caddy_repo 1
				apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null 2>&1 || die "apt-get update failed after adding Caddy's repository"
			fi
			web_pkg caddy
		fi
	fi
	[ "$NO_DOMAIN" = 0 ] || [ "$DRY" = 1 ] || chown caddy:caddy "$SUB_KEY" "$SUB_CERT"
	act install -d -m 0755 /etc/caddy/conf.d "$CADDY_ROUTES"
	if [ "$DRY" = 1 ]; then dry "add the line \"$CADDY_IMPORT\" to $cf (a fresh install gets a Caddyfile with only that line)"
	elif [ "$fresh" = 1 ] || [ ! -f "$cf" ]; then
		backup_file "$cf"
		printf '%s\n' "$CADDY_IMPORT" >"$cf"
		step "wrote $cf with one line: $CADDY_IMPORT"
	elif ! grep -qxF "$CADDY_IMPORT" "$cf"; then
		backup_file "$cf"
		printf '\n%s\n' "$CADDY_IMPORT" >>"$cf"
		step "added \"$CADDY_IMPORT\" to the end of $cf, the rest is untouched"
	fi
	if [ "${VEILWAY_CADDY_TLS:-}" = internal ]; then tls=$'\n\ttls internal'; fi
	if [ "$NO_DOMAIN" = 1 ]; then
		write_unit "$CADDY_SITE" <<EOF
# Written by veilway.sh install panel --no-domain. Remove it with: sudo bash veilway.sh uninstall web
http://:80 {
	respond 404
}
https://:$HTTPS_PORT {
	tls $SUB_CERT $SUB_KEY
	@sub path $sub $sub/*
	handle @sub {
		reverse_proxy 127.0.0.1:$PANEL_PORT
	}
	import $CADDY_ROUTES/*.caddy
	handle {
		respond 404
	}
}
$([ "$DECOY_ON" = 1 ] && printf 'http://:%s {\n\tbind 127.0.0.1\n\troot * %s\n\tfile_server\n}' "$DECOY_PORT" "$WEB_ROOT")
EOF
	else write_unit "$CADDY_SITE" <<EOF
# Written by veilway.sh install panel --domain. Remove it with: sudo bash veilway.sh uninstall web
$HTTPS_HOST {$tls
	handle $prefix/* {
		reverse_proxy 127.0.0.1:$PANEL_PORT
	}
	handle $sub/* {
		reverse_proxy 127.0.0.1:$PANEL_PORT
	}
	import $CADDY_ROUTES/*.caddy
	handle {
		root * $WEB_ROOT
		file_server
	}
}
$([ "$DECOY_ON" = 1 ] && printf 'http://:%s {\n\tbind 127.0.0.1\n\troot * %s\n\tfile_server\n}' "$DECOY_PORT" "$WEB_ROOT")
EOF
	fi
	if has_systemd && [ "$DRY" = 0 ]; then
		if ! { if [ "$fresh" = 1 ] || ! systemctl is-active --quiet caddy.service; then svc enable caddy.service; svc restart caddy.service; else svc reload caddy.service; fi; }; then
			rm -f -- "$CADDY_SITE"
			die "Caddy did not accept the new site, so it was taken back: see sudo journalctl -u caddy"
		fi
	else svc reload caddy.service; fi
	web_note web caddy
	if [ "$DRY" = 0 ] && [ "$NO_DOMAIN" = 1 ]; then step "Caddy serves https://$HTTPS_HOST$sub only, every other path answers 404"
	elif [ "$DRY" = 0 ]; then step "Caddy serves $HTTPS_HOST: the panel at $prefix and $sub, the plain site everywhere else"; fi
}

web_nginx() {
	local fresh=0 prefix="$1" sub="$2" cert="${VEILWAY_NGINX_CERT:-}" tls=""
	pkg_has nginx || fresh=1
	if [ -n "$cert" ] || [ "$NO_DOMAIN" = 1 ]; then web_pkg nginx; else web_pkg nginx certbot python3-certbot-nginx; fi
	if [ "$fresh" = 1 ] && [ -L /etc/nginx/sites-enabled/default ]; then
		act rm -f /etc/nginx/sites-enabled/default
		web_note nginx_default_removed 1
	fi
	act install -d -m 0755 "$NGINX_ROUTES"
	if [ -n "$cert" ]; then tls="	listen $HTTPS_PORT ssl;
	listen [::]:$HTTPS_PORT ssl;
	ssl_certificate ${cert%%:*};
	ssl_certificate_key ${cert#*:};"
	else tls="	# certbot adds the https part here"; fi
	if [ "$NO_DOMAIN" = 1 ]; then
		write_unit "$NGINX_SITE" <<EOF
# Written by veilway.sh install panel --no-domain. Remove it with: sudo bash veilway.sh uninstall web
server {
	listen $HTTPS_PORT ssl;
	listen [::]:$HTTPS_PORT ssl;
	server_tokens off;
	ssl_certificate $SUB_CERT;
	ssl_certificate_key $SUB_KEY;
	location ~ ^$sub(/|\$) {
		proxy_pass http://127.0.0.1:$PANEL_PORT;
		client_max_body_size 100m;
		proxy_set_header Host \$http_host;
		proxy_set_header X-Forwarded-For \$remote_addr;
	}
	include $NGINX_ROUTES/*.conf;
	location / {
		return 404;
	}
}
$([ "$DECOY_ON" = 1 ] && printf 'server {\n\tlisten 127.0.0.1:%s;\n\tserver_tokens off;\n\troot %s;\n\tlocation / {\n\t\ttry_files %s %s/ =404;\n\t}\n}' "$DECOY_PORT" "$WEB_ROOT" "\$uri" "\$uri")
EOF
	else write_unit "$NGINX_SITE" <<EOF
# Written by veilway.sh install panel --domain. Remove it with: sudo bash veilway.sh uninstall web
server {
	listen 80;
	listen [::]:80;
$tls
	server_name $DOMAIN;
	server_tokens off;
	root $WEB_ROOT;
	location ~ ^($prefix|$sub)(/|\$) {
		proxy_pass http://127.0.0.1:$PANEL_PORT;
		client_max_body_size 100m;
		proxy_set_header Host \$http_host;
		proxy_set_header X-Forwarded-For \$remote_addr;
	}
	include $NGINX_ROUTES/*.conf;
	location / {
		try_files \$uri \$uri/ =404;
	}
}
$([ "$DECOY_ON" = 1 ] && printf 'server {\n\tlisten 127.0.0.1:%s;\n\tserver_tokens off;\n\troot %s;\n\tlocation / {\n\t\ttry_files %s %s/ =404;\n\t}\n}' "$DECOY_PORT" "$WEB_ROOT" "\$uri" "\$uri")
EOF
	fi
	if has_systemd && [ "$DRY" = 0 ]; then
		if ! nginx -t >/dev/null 2>&1; then
			rm -f -- "$NGINX_SITE"
			die "nginx did not accept the new site, so it was taken back: see sudo nginx -t"
		fi
		if [ "$fresh" = 1 ] || ! systemctl is-active --quiet nginx.service; then svc enable nginx.service; svc restart nginx.service; else svc reload nginx.service; fi
	else svc reload nginx.service; fi
	web_note web nginx
	if [ "$DRY" = 0 ] && [ "$NO_DOMAIN" = 1 ]; then step "nginx serves https://$HTTPS_HOST$sub only, every other path answers 404"
	elif [ "$DRY" = 0 ]; then step "nginx serves $HTTPS_HOST: the panel at $prefix and $sub, the plain site everywhere else"; fi
	[ -z "$cert" ] && [ "$NO_DOMAIN" = 0 ] || return 0
	if [ "$DRY" = 1 ]; then dry "certbot --nginx -d $DOMAIN --https-port $HTTPS_PORT, with an https redirect"; return 0; fi
	web_note certbot_domain "$DOMAIN"
	if certbot --nginx -d "$DOMAIN" --https-port "$HTTPS_PORT" --non-interactive --agree-tos --register-unsafely-without-email --redirect; then step "certbot issued the certificate for $DOMAIN and turned on https"
		[ "$HTTPS_PORT" = 443 ] || { sed -i "s|return 301 https://\$host\$request_uri;|return 301 https://\$host:$HTTPS_PORT\$request_uri;|" "$NGINX_SITE"; svc reload nginx.service; }
	else warn "certbot could not get a certificate (the DNS record must point at this server and port 80 must be reachable). The site answers on http only until you run: sudo certbot --nginx -d $DOMAIN --https-port $HTTPS_PORT"; fi
}

# Checks the web server's config and reloads it. A failed reload leaves the server on its old config. A running Caddy is checked by its own reload, since caddy validate wants a home folder the update service does not have.
web_reload() {
	if [ "$1" = caddy ] && systemctl is-active --quiet caddy.service 2>/dev/null; then systemctl reload caddy.service >/dev/null 2>&1; return; fi
	case "$1" in caddy) caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 ;; *) nginx -t >/dev/null 2>&1 ;; esac || return 1
	! systemctl is-active --quiet "$1.service" 2>/dev/null || systemctl reload "$1.service" >/dev/null 2>&1
}

# Adds the line that includes the routes folder to a site file written before the panel could add routes, in front of the catch-all. The web server refusing it takes it back.
web_routes_include() {
	local site="$CADDY_SITE" dir="$CADDY_ROUTES" line="	import $CADDY_ROUTES/*.caddy" anchor="	handle {" saved
	if [ "$1" = nginx ]; then site="$NGINX_SITE"; dir="$NGINX_ROUTES"; line="	include $NGINX_ROUTES/*.conf;"; anchor="	location / {"; fi
	[ -f "$site" ] || return 0
	act install -d -m 0755 "$dir"
	grep -qF "$dir/" "$site" && return 0
	grep -qxF "$anchor" "$site" || { warn "$site has no place for the routes of the panel's Add to web server button: add the line \"${line#?}\" by hand before the last block"; return 1; }
	if [ "$DRY" = 1 ]; then dry "add \"${line#?}\" to $site, check the $1 config, reload $1 and take it back if $1 refuses it"; return 0; fi
	backup_file "$site"
	saved="$(mktemp "$VER_DIR/.site.XXXXXX")"
	cp -p "$site" "$saved"
	awk -v l="$line" -v a="$anchor" '!d && $0 == a { print l; d = 1 } { print }' "$saved" >"$site"
	if web_reload "$1"; then step "$site now includes $dir"
	else cp -p "$saved" "$site"; web_reload "$1" || true; warn "$1 did not accept the routes folder in $site, so it was taken back"; rm -f -- "$saved"; return 1; fi
	rm -f -- "$saved"
}

# The panel's answer to a web-routes request, a JSON file it can read in $UPDATE_DIR. It is made in $VER_DIR first, which only root can write, and moved in.
web_routes_result() {
	local tmp
	tmp="$(mktemp "$VER_DIR/.web-routes.XXXXXX")"
	printf '{"ok": %s, "message": "%s", "at": %s, "routes": %s, "web": "%s"}\n' "$1" "$2" "$(date +%s)" "$3" "$4" >"$tmp"
	chown root:veilway-panel "$tmp"; chmod 0640 "$tmp"
	mv -f "$tmp" "$UPDATE_DIR/web-routes.result"
}

# The panel's Add to web server button: web-routes.json in $UPDATE_DIR is the whole wanted set of ws and fronted paths, and replaces the file in the routes folder. It comes from a less trusted user, so each route is checked strictly, the target is always 127.0.0.1 and one bad route refuses all of them.
do_web_routes() {
	local w json="$UPDATE_DIR/web-routes.json" re='^/[A-Za-z0-9._~-][A-Za-z0-9._~/-]{11,127}$' err="" web raw lines="" path port type n=0 seen=" " f="$CONF_DIR/panel.json" prefix="/panel" sub="/sub" q extra fmt blk body="" file prev had=0
	need_root
	if [ "$DRY" = 1 ]; then dry "read $json, check every route, write the routes folder of the web server, check its config, reload it and write $UPDATE_DIR/web-routes.result"; return 0; fi
	web="$(web_state web)"
	if [ "$web" != caddy ] && [ "$web" != nginx ]; then web=""; err="this server has no web server that veilway.sh set up"
	elif { [ "$web" = caddy ] && [ ! -f "$CADDY_SITE" ]; } || { [ "$web" = nginx ] && [ ! -f "$NGINX_SITE" ]; }; then err="the site file veilway.sh wrote for $web is gone"
	elif ! has jq; then err="jq is not installed here"
	elif [ -L "$json" ] || [ ! -f "$json" ]; then err="the routes file is missing or is a link"
	else
		raw="$(timeout 5 head -c 65537 -- "$json" 2>/dev/null | tr -d '\0' || true)"
		if [ "$(printf '%s' "$raw" | wc -c)" -gt 65536 ]; then err="the routes file is over 64 KiB"
		elif ! lines="$(printf '%s' "$raw" | jq -r '.routes | if type == "array" then .[] else error("routes") end | if type == "object" and (.path | type) == "string" and (.type | type) == "string" and (.port | type) == "number" and .port == (.port | floor) then [.path, (.port | tostring), .type] | @tsv else error("route") end' 2>/dev/null)"; then err="the routes file is not JSON of the expected shape"; fi
	fi
	if [ -z "$err" ] && [ -f "$f" ]; then
		prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$f")"
		sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$f")"
		prefix="${prefix:-/panel}"; sub="${sub:-/sub}"
	fi
	if [ -z "$err" ] && [ -n "$lines" ]; then
		if [ "$web" = caddy ]; then fmt='handle %s* {\n\treverse_proxy 127.0.0.1:%s {\n\t\theader_down -Server\n\t}\n}\n'
		else fmt='location %s {\n\tproxy_pass http://127.0.0.1:%s;\n\tproxy_http_version 1.1;\n\tproxy_set_header Upgrade $http_upgrade;\n\tproxy_set_header Connection "upgrade";\n\tproxy_set_header Host $host;\n\tproxy_set_header X-Forwarded-For $remote_addr;%b\n}\n'; fi
		while IFS=$'\t' read -r path port type; do
			n=$((n + 1))
			if [ "$n" -gt 32 ]; then err="there are more than 32 routes"; break; fi
			if ! [[ "$path" =~ $re ]] || [[ "$path" == *//* || "$path" == *..* ]]; then err="route $n has a path that is not allowed"; break; fi
			for q in "$prefix" "$sub"; do if [[ "$q/" == "$path"* || "$path/" == "$q/"* ]]; then err="route $n is the panel's own path or runs into it"; break 2; fi; done
			if [[ "$seen" == *" $path "* ]]; then err="route $n repeats a path"; break; fi
			seen+="$path "
			if ! [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$port" -gt 65535 ]; then err="route $n has a port that is not 1 to 65535"; break; fi
			case "$type" in ws) extra="" ;; fronted) extra='\n\tproxy_buffering off;\n\tproxy_read_timeout 1h;' ;; *) err="route $n is not ws or fronted"; break ;; esac
			if [ "$web" = caddy ]; then printf -v blk "$fmt" "$path" "$port"; else printf -v blk "$fmt" "$path" "$port" "$extra"; fi
			body+="$blk"
		done <<<"$lines"
	fi
	if [ -z "$err" ]; then
		file="$NGINX_ROUTES/panel.conf"; [ "$web" != caddy ] || file="$CADDY_ROUTES/panel.caddy"
		prev="$(mktemp "$VER_DIR/.routes.XXXXXX")"
		if [ -f "$file" ]; then cp -p "$file" "$prev"; had=1; fi
		if ! web_routes_include "$web"; then err="the site file of $web has no place for the routes"
		else
			printf '# The Add to web server button of the panel writes this file: edits here are overwritten.\n%s' "$body" >"$file.new"
			chmod 0644 "$file.new"; mv -f "$file.new" "$file"
			if ! web_reload "$web"; then
				if [ "$had" = 1 ]; then cp -p "$prev" "$file"; else rm -f -- "$file"; fi
				web_reload "$web" || true
				err="$web did not accept the routes, so they were taken back"
			fi
		fi
		rm -f -- "$prev"
	fi
	rm -f -- "$json"
	if [ -n "$err" ]; then warn "web routes refused: $err"; web_routes_result false "Nothing was changed: $err." 0 "$web"
	else w="paths"; [ "$n" != 1 ] || w="path"; step "$web serves $n $w of the panel"; web_routes_result true "$n $w of the panel $([ "$n" = 1 ] && echo is || echo are) live on $web." "$n" "$web"; fi
}

# The panel answers every path it does not serve with its not_found, and the web server's own 404 answers the rest of the site. They have to be the same bytes, or the panel's paths can be told apart.
web_not_found() {
	local f="$CONF_DIR/panel.json" headers body new
	if [ "$DRY" = 1 ]; then dry "set not_found in $f to $WEB's own 404 answer"; return 0; fi
	if [ "$WEB" = caddy ]; then headers='[]'; body=""
	else headers='[["content-type", "text/html"]]'; printf -v body '<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n'; fi
	new="$(jq --argjson h "$headers" --arg b "$body" '.not_found = {status: 404, headers: $h, body: $b}' "$f")" || die "cannot read $f as JSON"
	jq -e '.not_found' "$f" >/dev/null 2>&1 || web_note not_found_set 1
	backup_file "$f"
	printf '%s\n' "$new" >"$f.new"
	chown root:veilway-panel "$f.new"; chmod 0640 "$f.new"
	mv -f "$f.new" "$f"
	step "set not_found in $f to $WEB's own 404 answer"
}

# Sets up the web server for the panel's domain: packages, the site file, the plain site, the panel's not_found. It runs before the panel is restarted, so the restart picks up not_found.
web_setup() {
	local f="$CONF_DIR/panel.json" prefix="/panel" sub="/sub"
	step "web server ($WEB) for $HTTPS_HOST"
	if [ -f "$f" ]; then
		prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$f")"
		sub="$(sed -n 's/.*"sub_path": *"\([^"]*\)".*/\1/p' "$f")"
	fi
	if [ "$NO_DOMAIN" = 1 ]; then
		if [ "$DRY" = 1 ]; then dry "make $SUB_KEY (EC P-256) if there is none, and a self-signed certificate for $PUBLIC_IP valid 10 years in $SUB_CERT, both mode 600"
		else
			install -d -m 0755 "$SUB_TLS"
			[ -f "$SUB_KEY" ] || ( umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$SUB_KEY" ) || die "openssl could not make the key"
			if [ ! -f "$SUB_CERT" ] || [ "$(web_state ip)" != "$PUBLIC_IP" ]; then
				( umask 077; openssl req -new -x509 -key "$SUB_KEY" -days 3650 -subj "/CN=$PUBLIC_IP" -addext "subjectAltName=IP:$PUBLIC_IP" -out "$SUB_CERT" ) || die "openssl could not make the certificate"
				step "made a self-signed certificate for $PUBLIC_IP, valid 10 years"
			else info "kept the certificate for $PUBLIC_IP"; fi
			chmod 0600 "$SUB_KEY" "$SUB_CERT"
			web_note pin "$(openssl x509 -in "$SUB_CERT" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64 | tr -d '\n')"
		fi
	fi
	web_note mode "$([ "$NO_DOMAIN" = 1 ] && echo ip || echo domain)"
	web_note domain "$DOMAIN"
	web_note ip "$PUBLIC_IP"
	web_note https_port "$HTTPS_PORT"
	web_free_https
	web_pkg jq
	web_decoy
	if [ -n "$(ss -H -ltnp "sport = :$DECOY_PORT" | grep -vE '"(caddy|nginx)"' || true)" ]; then warn "127.0.0.1:$DECOY_PORT is used by something else here, so the plain site is not served there. A node's decoy origin needs a web page: pick another port with VEILWAY_DECOY_PORT=<port> and run this again, or point the origin at your own page."
	else DECOY_ON=1; [ "$DRY" = 0 ] || dry "serve the same plain site over http on 127.0.0.1:$DECOY_PORT only, in the same site file, as the default decoy origin of a node's transports"; fi
	if [ "$WEB" = caddy ]; then web_caddy "$prefix" "$sub"; else web_nginx "$prefix" "$sub"; fi
	web_not_found
}

# Takes back what web_setup and update recorded in $WEB_STATE: the site file, the decoy site file, the routes folder, the import line, the plain site if nobody edited it, not_found, and the packages it installed. The node's moved transports stay where they are.
do_uninstall_web() {
	local web domain p sha pkgs rest port from to moved
	need_root
	[ -f "$WEB_STATE" ] || die "no web server setup by this script is recorded here"
	web="$(web_state web)"; domain="$(web_state domain)"; pkgs="$(web_state pkgs)"; port="$(web_state https_port)"
	[ -n "$domain" ] || domain="$(web_state ip)"
	confirm "Remove the web server setup for $domain ($web on port ${port:-443}): its site file, the plain site if it is unchanged, the panel's not_found${pkgs:+, and the packages ${pkgs# }}?" || die "cancelled"
	[ -z "$(web_state decoy_file)" ] || act rm -f -- "$(web_state decoy_file)"
	case "$web" in
		caddy)
			act rm -f -- "$CADDY_SITE"
			act rm -rf -- "$CADDY_ROUTES"
			if [ -f /etc/caddy/Caddyfile ] && [ "$DRY" = 1 ]; then dry "remove the line \"$CADDY_IMPORT\" from /etc/caddy/Caddyfile"
			elif [ -f /etc/caddy/Caddyfile ]; then rest="$(grep -vxF "$CADDY_IMPORT" /etc/caddy/Caddyfile || true)"; printf '%s\n' "$rest" >/etc/caddy/Caddyfile; fi
			act rmdir /etc/caddy/conf.d 2>/dev/null || true
			;;
		nginx)
			act rm -f -- "$NGINX_SITE"
			act rm -rf -- "$NGINX_ROUTES"
			if [ -n "$(web_state certbot_domain)" ] && has certbot; then act certbot delete --cert-name "$domain" --non-interactive || true; fi
			if [ "$(web_state nginx_default_removed)" = 1 ] && [ -e /etc/nginx/sites-available/default ]; then act ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default; fi
			;;
	esac
	[ "$(web_state mode)" != ip ] || act rm -rf -- "$SUB_TLS"
	sha="$(web_state decoy_sha)"
	if [ -n "$sha" ] && [ -f "$WEB_ROOT/index.html" ] && [ "$(sha256sum "$WEB_ROOT/index.html" | cut -d' ' -f1)" = "$sha" ] && [ "$(find "$WEB_ROOT" -mindepth 1 | wc -l)" = 1 ]; then act rm -rf -- /var/www/veilway-site
	elif [ -e "$WEB_ROOT" ]; then info "kept $WEB_ROOT: it was edited or holds other files"; fi
	if [ "$(web_state not_found_set)" = 1 ] && [ -f "$CONF_DIR/panel.json" ] && has jq; then
		if [ "$DRY" = 1 ]; then dry "remove not_found from $CONF_DIR/panel.json and restart the panel"
		else
			jq 'del(.not_found)' "$CONF_DIR/panel.json" >"$CONF_DIR/panel.json.new"
			chown root:veilway-panel "$CONF_DIR/panel.json.new"; chmod 0640 "$CONF_DIR/panel.json.new"
			mv -f "$CONF_DIR/panel.json.new" "$CONF_DIR/panel.json"
			svc restart veilway-panel.service || true
		fi
	fi
	for p in $pkgs; do case "$p" in caddy | nginx) svc stop "$p.service" || true ;; esac; done
	# shellcheck disable=SC2086
	[ -z "$pkgs" ] || act env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 remove -y -qq $pkgs
	[[ " $pkgs " == *" $web "* ]] || svc reload "$web.service" || true
	if [ "$(web_state caddy_repo)" = 1 ]; then
		act rm -f /etc/apt/sources.list.d/caddy-stable.list /usr/share/keyrings/caddy-stable-archive-keyring.gpg
		[ "$DRY" = 1 ] || apt-get -o DPkg::Lock::Timeout=600 update -qq >/dev/null 2>&1 || true
	fi
	moved="$(web_state node_moved)"; [ -n "$moved" ] || [ -z "$(web_state node_443_moved)" ] || moved="443 8443"; if [ -n "$moved" ]; then read -r from to <<<"$moved"; warn "the node's TCP transports stay on $to: move them back in the panel if you want $from"; fi
	act rm -f -- "$WEB_STATE"
	[ "$DRY" = 1 ] || step "web server setup removed"
}

# The test overrides move downloads and trusted keys away from the release channel, so each one is shown and needs a yes.
accept_overrides() {
	local v
	[ "${#OVERRIDES[@]}" -gt 0 ] || return 0
	warn "test overrides are set, so downloads and keys do not come from the release channel:"
	for v in "${OVERRIDES[@]}"; do info "$v"; done
	[ "$DRY" = 1 ] && return 0
	if [ "$ASSUME_YES" = 1 ]; then [ "${VEILWAY_TESTING:-}" = 1 ] || die "test overrides with --yes need VEILWAY_TESTING=1"; return 0; fi
	[ "$(ask "Use these test overrides? [y/N]" n | tr '[:upper:]' '[:lower:]')" = y ] || die "cancelled"
}

main() {
	local args=() cmd env_mirrors=() unique=() m
	while [ $# -gt 0 ]; do
		case "$1" in
			--dry-run) DRY=1 ;;
			--yes | -y) ASSUME_YES=1 ;;
			--allow-downgrade) ALLOW_DOWNGRADE=1 ;;
			--mirror-only) MIRROR_ONLY=1 ;;
			--mirror) [ $# -gt 1 ] || die "--mirror needs an https url"; MIRRORS+=("$2"); shift ;;
			--mirror=*) MIRRORS+=("${1#*=}") ;;
			--domain) [ $# -gt 1 ] || die "--domain needs a domain name"; DOMAIN="$2"; shift ;;
			--domain=*) DOMAIN="${1#*=}" ;;
			--web) [ $# -gt 1 ] || die "--web needs caddy or nginx"; WEB="$2"; shift ;;
			--web=*) WEB="${1#*=}" ;;
			--https-port) [ $# -gt 1 ] || die "--https-port needs a port number"; HTTPS_PORT="$2"; shift ;;
			--https-port=*) HTTPS_PORT="${1#*=}" ;;
			--no-domain) NO_DOMAIN=1 ;;
			--no-two-step) TWO_STEP=off ;;
			--ip) [ $# -gt 1 ] || die "--ip needs an IPv4 address"; PUBLIC_IP="$2"; shift ;;
			--ip=*) PUBLIC_IP="${1#*=}" ;;
			--version=*) WANT_VERSION="${1#*=}" ;;
			--version) if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then WANT_VERSION="$2"; shift; else args+=(version); fi ;;
			-h | --help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
			*) args+=("$1") ;;
		esac
		shift
	done
	[ -z "$WANT_VERSION" ] || [[ "$WANT_VERSION" =~ $TAG_RE ]] || die "that version is not a release tag"
	read -r -a env_mirrors <<<"${VEILWAY_MIRRORS:-}"
	MIRRORS+=(${env_mirrors[@]+"${env_mirrors[@]}"})
	for m in ${MIRRORS[@]+"${MIRRORS[@]}"}; do
		m="${m%/}"
		[[ "$m" =~ $MIRROR_RE && "${m#*://}" != *//* && "$m" != *..* ]] || die "\"$m\" is not a mirror address: it must be https://host[/path], or http:// on loopback for tests"
		[[ " ${unique[*]:-} " == *" $m "* ]] || unique+=("$m")
	done
	MIRRORS=(${unique[@]+"${unique[@]}"})
	SOURCES=(${unique[@]+"${unique[@]}"})
	[ "$MIRROR_ONLY" = 0 ] || [ "${#MIRRORS[@]}" -gt 0 ] || die "--mirror-only needs a mirror: give --mirror <url> or set VEILWAY_MIRRORS"
	[ "$MIRROR_ONLY" = 1 ] || SOURCES+=("$RELEASE_BASE")
	[[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$PANEL_PORT))" -ge 1 ] && [ "$((10#$PANEL_PORT))" -le 65535 ] || die "VEILWAY_PANEL_PORT must be a port from 1 to 65535"
	PANEL_PORT=$((10#$PANEL_PORT))
	accept_overrides
	[ "$DRY" = 1 ] && warn "dry run: nothing will be changed"
	cmd="${args[0]:-}"
	[ "${#args[@]}" -gt 0 ] && args=("${args[@]:1}")
	case "$cmd" in
		"") menu ;;
		install) header; if [ "${args[0]:-}" = relay ]; then do_install_relay "${args[@]:1}"; else do_install "${args[0]:-}"; fi ;;
		update) header; do_update "${args[0]:-both}" ;;
		panel-update-request) do_panel_update_request ;;
		status) do_status ;;
		logs) do_logs "${args[0]:-node}" ;;
		restart) do_restart "${args[0]:-both}" ;;
		check | config-check) run_check ;;
		doctor) do_doctor ;;
		backup) do_backup "${args[0]:-}" ;;
		restore) do_restore "${args[0]:-}" ;;
		uninstall) header; case "${args[0]:-}" in relay) do_uninstall_relay ;; web) do_uninstall_web ;; *) do_uninstall ;; esac ;;
		mirror-sync) header; do_mirror_sync "${args[0]:-}" ;;
		version) do_version ;;
		addon) header; do_addon "${args[0]:-}" "${args[1]:-install}" ;;
		panel-prefix) header; do_panel_prefix "${args[0]:-}" ;;
		admin) do_admin "${args[0]:-list}" "${args[1]:-}" ;;
		*) die "unknown command \"$cmd\": try install, update, status, logs, restart, check, doctor, backup, restore, panel-prefix, admin, mirror-sync, uninstall, version" ;;
	esac
}

main "$@"
