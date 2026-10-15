#!/usr/bin/env bash
# Veilway installer and manager for Linux servers (systemd; x86_64 and aarch64).
#
#   curl -fsSL https://raw.githubusercontent.com/veilway-project/veilway/main/scripts/veilway.sh | sudo bash
#   sudo bash veilway.sh                      interactive menu
#   sudo bash veilway.sh install node|panel|both [--version vX.Y.Z]
#   sudo bash veilway.sh update [node|panel|both]
#   bash veilway.sh status | logs [node|panel] | restart [node|panel|both]
#   sudo bash veilway.sh check | doctor
#   sudo bash veilway.sh backup [file] | restore <file> | uninstall | version
#   sudo bash veilway.sh addon xray [install|remove|status]
#   Flags: --dry-run (print what would happen, change nothing), --yes (no questions), --version <tag>
#
# Every download is checked with minisign against the public key below, and the signature's trusted
# comment must read "veilway <tag> <asset>" for the node and "veilway-panel <tag> <asset>" for the panel.
# Nothing is installed without that check.
# Environment: NO_COLOR, VEILWAY_PANEL_PORT (default 8480).
# For testing only, to run against a release server of your own (scripts/gate-alpha.sh does): VEILWAY_RELEASE_BASE
# (default https://github.com, still https only), VEILWAY_RAW_BASE (default https://raw.githubusercontent.com),
# VEILWAY_NODE_PUBKEY and VEILWAY_PANEL_PUBKEY (default: the key below). They change where a download comes from
# and which key is trusted. The checks themselves are the same. Each one is printed and needs a yes; with --yes, VEILWAY_TESTING=1 too.
set -euo pipefail
umask 022

SCRIPT_VERSION="1.0.0"
CORE_REPO="veilway-project/veilway"
PANEL_REPO="veilway-project/veilway-panel"
PUBKEY="RWQiodKlFCiJ3bkZD3ojKV7AYyTYf3F5x/XY8upWvpSFTVm3O2cNRbrV"
NODE_PUBKEY="${VEILWAY_NODE_PUBKEY:-$PUBKEY}"
PANEL_PUBKEY="${VEILWAY_PANEL_PUBKEY:-$PUBKEY}"
RELEASE_BASE="${VEILWAY_RELEASE_BASE:-https://github.com}"
RAW_BASE="${VEILWAY_RAW_BASE:-https://raw.githubusercontent.com}"
PANEL_PORT="${VEILWAY_PANEL_PORT:-8480}"
TAG_RE='^v?[0-9A-Za-z._-]+$'
OVERRIDES=()
for v in VEILWAY_RELEASE_BASE VEILWAY_RAW_BASE VEILWAY_NODE_PUBKEY VEILWAY_PANEL_PUBKEY; do if [ -n "${!v:-}" ]; then OVERRIDES+=("$v=${!v}"); fi; done
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/veilway"
NODE_DIR="$CONF_DIR/node"
STATE_DIR="/var/lib/veilway"
ADDON_DIR="/usr/local/lib/veilway/addons"
XRAY_RELEASE="v26.3.27"
PANEL_DIR="/var/lib/veilway-panel"
VER_DIR="/var/lib/veilway-installer"
BACKUP_DIR="/var/backups/veilway"
UNIT_DIR="/etc/systemd/system"
DRY=0
ASSUME_YES=0
WANT_VERSION=""
TMP=""

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
	B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; Z=$'\033[0m'
else
	B=""; D=""; R=""; G=""; Y=""; C=""; Z=""
fi
if [ -t 1 ] && grep -qi 'utf-\?8' <<<"${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"; then
	OK="✓"; BAD="✗"; DOT="·"; SPIN='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; H="─"; V="│"; TL="┌"; TR="┐"; BL="└"; BR="┘"
else
	OK="+"; BAD="x"; DOT="-"; SPIN="|/-\\"; H="-"; V="|"; TL="+"; TR="+"; BL="+"; BR="+"
fi

cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
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
	printf '  %s%s %s%s%s %s%s\n' "$D" "$TL" "$Z$B" "$title" "$Z$D" "$(rule $((w - ${#title} - 3)))" "$TR$Z"
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

pkg_install() {
	if has apt-get; then [ "$DRY" = 1 ] || apt-get update -qq >/dev/null 2>&1 || true; act env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
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
			die "minisign is not available from your package manager. Install it (https://jedisct1.github.io/minisign/) and run this again. Downloads are never installed unchecked."
		fi
		[ "$DRY" = 1 ] || has minisign || die "minisign did not install"
	fi
	has setpriv || die "setpriv (util-linux) is needed to write the node's files as the node user"
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

fetch() {
	local url="$1" out="$2" msg="$3" rc=0
	curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --connect-timeout 15 -o "$out" "$url" &
	spin $! "$msg" || rc=$?
	[ "$rc" = 0 ] || die "download failed: $url"
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

# Downloads one asset with its signature into $TMP and refuses unless both the signature and the trusted comment match.
download_verified() {
	local repo="$1" key="$2" name="$3" tag="$4" product="$5" base out comment
	base="$RELEASE_BASE/$repo/releases/download/$tag"
	out="$TMP/$name"
	fetch "$base/$name" "$out" "downloading $name $tag"
	fetch "$base/$name.minisig" "$out.minisig" "downloading signature"
	out="$(minisign -V -m "$TMP/$name" -x "$TMP/$name.minisig" -P "$key" 2>&1)" || die "signature check failed for $name: $out"
	comment="$(printf '%s\n' "$out" | sed -n 's/^Trusted comment: //p' | head -n 1)"
	[ "$comment" = "$product $tag $name" ] || die "signature is for \"$comment\", expected \"$product $tag $name\": refusing"
	step "signature verified ($name $tag)"
}

release_tag() { if [ -n "$WANT_VERSION" ]; then printf '%s' "$WANT_VERSION"; else latest_tag "$1"; fi; }

install_binary() {
	local src="$1" dest="$2"
	install -m 0755 "$src" "$dest.new"
	mv -f "$dest.new" "$dest"
}

fetch_and_install() {
	local which="$1" repo key name dest tag product cur vf
	if [ "$which" = node ]; then repo="$CORE_REPO"; key="$NODE_PUBKEY"; product=veilway; name="veilway-$TARGET"; dest="$BIN_DIR/veilway"
	else repo="$PANEL_REPO"; key="$PANEL_PUBKEY"; product=veilway-panel; name="veilway-panel-$TARGET"; dest="$BIN_DIR/veilway-panel"; fi
	if [ "$DRY" = 1 ]; then
		dry "resolve ${WANT_VERSION:-the latest tag} of $repo"
		dry "download $name and $name.minisig, verify with minisign key ${key:0:12}..., match comment \"$product <tag> $name\""
		dry "install -m 0755 $dest"
		return 0
	fi
	tag="$(release_tag "$repo")"
	cur="$(installed_version "$which")"
	if [ -z "$WANT_VERSION" ] && [ -n "$cur" ] && [ "$cur" != "$tag" ] && [ "$(printf '%s\n%s\n' "$cur" "$tag" | sort -V | head -n 1)" = "$tag" ]; then
		die "$tag is older than the installed $cur: refusing a downgrade (pass --version $tag to do it on purpose)"
	fi
	download_verified "$repo" "$key" "$name" "$tag" "$product"
	install_binary "$TMP/$name" "$dest"
	step "installed $dest ($tag)"
	install -d -m 0755 "$VER_DIR"
	vf="$(mktemp "$VER_DIR/.$which.XXXXXX")"
	printf '%s\n' "$tag" >"$vf"; chmod 0644 "$vf"; mv -f "$vf" "$VER_DIR/$which.version"
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
ReadWritePaths=$PANEL_DIR
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
	step "node"
	ensure_user veilway "$STATE_DIR"
	act install -d -m 0750 -o veilway -g veilway "$STATE_DIR"
	act install -d -m 0750 -o root -g veilway "$CONF_DIR"
	fetch_and_install node
	prepare_node_dir
	node_unit
	daemon_reload
	if [ "$DRY" = 1 ]; then
		dry "write $CONF_DIR/config.example.json from the release tag"
		dry "write $NODE_DIR/config.json if there is none: no inbound and one direct exit, for the panel to fill in"
	else
		tag="$(installed_version node)"
		if [ ! -f "$CONF_DIR/config.example.json" ] && curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "$CONF_DIR/config.example.json" "$RAW_BASE/$CORE_REPO/${tag:-main}/config.example.json" 2>/dev/null; then
			step "wrote $CONF_DIR/config.example.json"
		fi
		# A node needs a config to run, and the panel needs a running node to change it, so a fresh install starts with a node that has no inbound.
		if [ ! -e "$NODE_DIR/config.json" ]; then
			( umask 077; as_node_user tee "$NODE_DIR/config.json" >/dev/null ) <<'EOF'
{
	"version": 1,
	"dns": {"servers": ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]},
	"inbounds": [],
	"users": [],
	"outbounds": [{"tag": "plain", "type": "direct"}],
	"exits": [{"tag": "main", "name": "This server", "backend": {"type": "netstack", "outbound": "plain"}}],
	"routing": {"default": "main", "rules": [
		{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"},
		{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}
	]}
}
EOF
			step "wrote $NODE_DIR/config.json: no inbound yet, add one in the panel"
		fi
		chown -h veilway:veilway "$NODE_DIR/config.json"
		as_node_user chmod 0600 "$NODE_DIR/config.json"
	fi
	if run_check; then svc enable veilway.service; svc restart veilway.service; else warn "config has errors: the node was not restarted"; fi
}

install_panel() {
	step "panel"
	ensure_user veilway "$STATE_DIR"
	ensure_user veilway-panel "$PANEL_DIR"
	act install -d -m 0750 -o veilway-panel -g veilway-panel "$PANEL_DIR"
	act install -d -m 0750 -o root -g veilway "$CONF_DIR"
	fetch_and_install panel
	panel_config
	panel_unit
	daemon_reload
	svc enable veilway-panel.service
	svc restart veilway-panel.service
	panel_summary
}

# Written once: an existing panel.json is never touched. The prefix is random, so the admin pages are not at a guessable path.
panel_config() {
	local f="$CONF_DIR/panel.json" prefix
	if [ "$DRY" = 1 ]; then dry "write $f (loopback 127.0.0.1:$PANEL_PORT, random prefix, keys and database under $PANEL_DIR)"; return 0; fi
	[ -f "$f" ] && { info "kept existing $f"; return 0; }
	prefix="/p-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	cat >"$f" <<EOF
{
	"listen": "127.0.0.1:$PANEL_PORT",
	"prefix": "$prefix",
	"sub_path": "/sub",
	"database": "$PANEL_DIR/panel.db",
	"keys": "$PANEL_DIR/panel.keys",
	"signing": "$PANEL_DIR/signing.keys",
	"node_socket": "/run/veilway/control.sock",
	"trusted_proxies": ["127.0.0.1", "::1"],
	"allowed_hosts": [],
	"secure_cookies": true
}
EOF
	chown root:veilway-panel "$f"
	chmod 0640 "$f"
	step "wrote $f"
}

panel_summary() {
	local token="" prefix="/panel" sub="/sub" i
	[ -f "$CONF_DIR/panel.json" ] && prefix="$(sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' "$CONF_DIR/panel.json")"
	if [ "$DRY" != 1 ] && has_systemd; then
		for i in 1 2 3 4 5 6 7 8 9 10; do
			token="$(journalctl -u veilway-panel --no-pager -o cat 2>/dev/null | sed -n 's/^Setup token (one time): //p' | tail -n 1 || true)"
			[ -n "$token" ] && break
			sleep 1
		done
	fi
	printf '\n'
	box "Panel" \
		"Listens on 127.0.0.1:$PANEL_PORT only. Put your web server in front:" \
		"" \
		"  nginx:  location ~ ^($prefix|$sub)(/|\$) {" \
		"            proxy_pass http://127.0.0.1:$PANEL_PORT;" \
		"            proxy_set_header Host \$host;" \
		"            proxy_set_header X-Forwarded-For \$remote_addr; }" \
		"" \
		"  Caddy:  panel.example.com {" \
		"            reverse_proxy $prefix/* 127.0.0.1:$PANEL_PORT" \
		"            reverse_proxy $sub/* 127.0.0.1:$PANEL_PORT }" \
		"" \
		"Admin pages: https://your-domain$prefix/" \
		"$([ -n "$token" ] && echo "Setup token (one time): $token" || echo "Setup token: sudo journalctl -u veilway-panel | grep 'Setup token'")" \
		"Send it with a username and password to POST $prefix/api/setup."
}

pick_component() {
	case "${1:-}" in
		node | panel | both) printf '%s' "$1" ;;
		"") printf '%s' "$(ask "Install node, panel, or both? [both]" both)" ;;
		*) die "choose node, panel or both" ;;
	esac
}

do_install() {
	local what comp
	comp="$(pick_component "${1:-}")"
	what="$comp"
	need_root
	refuse_links
	detect_target
	ensure_tools
	[ "$DRY" = 1 ] || { TMP="$(mktemp -d)"; install -d -m 0755 "$STATE_DIR" 2>/dev/null || true; }
	has_systemd || [ "$DRY" = 1 ] || warn "systemd is not running: units are written but nothing is started"
	[ "$DRY" = 1 ] || { mkdir -p "$STATE_DIR" "$PANEL_DIR"; }
	case "$what" in
		node) install_node ;;
		panel) install_panel ;;
		both) install_node; install_panel ;;
	esac
	printf '\n'
	step "done. Check the state any time with: sudo bash veilway.sh status"
}

do_update() {
	local comp="${1:-both}" cur
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
			prepare_node_dir
			node_unit
			[ -f "$UNIT_DIR/veilway-xray.service" ] && xray_units
			daemon_reload
			svc restart veilway.service
		else info "node is not installed, skipped"; fi
	fi
	if [ "$comp" = panel ] || [ "$comp" = both ]; then
		if [ -x "$BIN_DIR/veilway-panel" ] || [ "$DRY" = 1 ]; then
			cur="$(installed_version panel)"
			info "panel is at ${cur:-unknown}"
			fetch_and_install panel
			svc restart veilway-panel.service
		else info "panel is not installed, skipped"; fi
	fi
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
	local v
	header
	printf '  %s%-14s %-34s %s%s\n' "$B" "Part" "State" "Version" "$Z"
	printf '  %s%s%s\n' "$D" "$(rule 62)" "$Z"
	v="$(installed_version node)"; v="${v:--}"
	[ -x "$BIN_DIR/veilway" ] || v="not installed"
	printf '  %-14s %-34s %s\n' "node" "$(unit_state veilway.service)" "$v"
	v="$(installed_version panel)"; v="${v:--}"
	[ -x "$BIN_DIR/veilway-panel" ] || v="not installed"
	printf '  %-14s %-34s %s\n' "panel" "$(unit_state veilway-panel.service)" "$v"
	printf '  %-14s %-34s %s\n' "config" "$([ -f "$NODE_DIR/config.json" ] && echo present || echo missing)" "$NODE_DIR/config.json"
	printf '  %-14s %-34s %s\n' "state" "$([ -d "$STATE_DIR" ] && echo present || echo missing)" "$STATE_DIR"
	printf '  %-14s %-34s %s\n' "backups" "$(find "$BACKUP_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ') files" "$BACKUP_DIR"
	printf '\n'
}

do_logs() {
	local unit="veilway.service"
	[ "${1:-node}" = panel ] && unit="veilway-panel.service"
	has_systemd || die "logs come from journald, and systemd is not running here"
	if [ "$DRY" = 1 ]; then dry "journalctl -u $unit -n 100 -f"; return 0; fi
	exec journalctl -u "$unit" -n 100 -f --no-pager
}

do_restart() {
	local comp="${1:-both}"
	need_root
	[ "$comp" = panel ] || svc restart veilway.service
	[ "$comp" = node ] || svc restart veilway-panel.service
}

node_flags() { printf '%s\n' --config "$NODE_DIR/config.json" --state "$STATE_DIR/veilway-state.json" --replay "$STATE_DIR/veilway-replay" --api /run/veilway/control.sock; }

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

backup_paths() { printf '%s\n' "${CONF_DIR#/}" "${STATE_DIR#/}/veilway-state.json" "${PANEL_DIR#/}"; }

do_backup() {
	local out="${1:-$BACKUP_DIR/veilway-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}" p existing=()
	need_root
	while read -r p; do [ -e "/$p" ] && existing+=("$p"); done < <(backup_paths)
	[ "${#existing[@]}" -gt 0 ] || { warn "nothing to back up yet"; return 0; }
	# The replay memory is left out on purpose: restoring an old one would let old packets replay.
	if [ "$DRY" = 1 ]; then dry "tar czf $out ${existing[*]}"; return 0; fi
	mkdir -p "$(dirname "$out")"
	chmod 0700 "$(dirname "$out")" 2>/dev/null || true
	(umask 077; tar -czf "$out" -C / "${existing[@]}")
	step "backup written to $out (holds keys: keep it private)"
}

do_restore() {
	local file="${1:-}"
	need_root
	refuse_links
	[ -n "$file" ] || die "usage: veilway.sh restore <backup.tar.gz>"
	[ -r "$file" ] || [ "$DRY" = 1 ] || die "cannot read $file"
	confirm "Restore $file over $CONF_DIR, the usage state and the panel data?" || die "cancelled"
	if [ "$DRY" = 1 ]; then dry "stop services, save current files to $BACKUP_DIR, extract $file to /, fix owners, start services"; return 0; fi
	grep -qE '(^/|(^|/)\.\.(/|$))' <<<"$(tar -tzf "$file")" && die "the archive has unsafe paths: refusing"
	grep -q '^[lh]' <<<"$(tar -tvzf "$file")" && die "the archive has links: refusing"
	do_backup "$BACKUP_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" || true
	svc stop veilway.service; svc stop veilway-panel.service
	tar -xzf "$file" -C / --no-same-owner
	id veilway >/dev/null 2>&1 && { chown root:veilway "$CONF_DIR"; chmod 0750 "$CONF_DIR"; prepare_node_dir; chown -h -R veilway:veilway "$NODE_DIR"; chown -h veilway:veilway "$STATE_DIR/veilway-state.json" 2>/dev/null || true; }
	chown -h root:veilway-panel "$CONF_DIR/panel.json" 2>/dev/null || true
	id veilway-panel >/dev/null 2>&1 && chown -h -R veilway-panel:veilway-panel "$PANEL_DIR"
	svc start veilway.service; svc start veilway-panel.service
	step "restored from $file"
}

do_uninstall() {
	need_root
	confirm "Remove Veilway binaries, units and users? Backups in $BACKUP_DIR stay." || die "cancelled"
	do_backup || true
	svc stop veilway.service || true; svc stop veilway-panel.service || true
	svc disable veilway.service || true; svc disable veilway-panel.service || true
	svc stop veilway-xray.socket || true; svc stop veilway-xray.service || true; svc disable veilway-xray.socket || true
	act rm -f "$UNIT_DIR/veilway.service" "$UNIT_DIR/veilway-panel.service" "$UNIT_DIR/veilway-xray.socket" "$UNIT_DIR/veilway-xray.service" "$BIN_DIR/veilway" "$BIN_DIR/veilway-panel"
	act rm -rf "$ADDON_DIR"
	daemon_reload
	if confirm "Also delete $CONF_DIR, $STATE_DIR and $PANEL_DIR? The backup above keeps a copy."; then
		act rm -rf "$CONF_DIR" "$STATE_DIR" "$PANEL_DIR"
		has userdel && { act userdel veilway 2>/dev/null || true; act userdel veilway-panel 2>/dev/null || true; act userdel veilway-xray 2>/dev/null || true; }
		has deluser && ! has userdel && { act deluser veilway 2>/dev/null || true; act deluser veilway-panel 2>/dev/null || true; act deluser veilway-xray 2>/dev/null || true; }
	else info "config and data kept"; fi
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

menu() {
	local c
	header
	while true; do
		printf '  %s1%s Install    %s2%s Update     %s3%s Status     %s4%s Logs\n' "$B" "$Z" "$B" "$Z" "$B" "$Z" "$B" "$Z"
		printf '  %s5%s Restart    %s6%s Check      %s7%s Doctor     %s8%s Backup\n' "$B" "$Z" "$B" "$Z" "$B" "$Z" "$B" "$Z"
		printf '  %s9%s Restore    %s10%s Uninstall %s0%s Quit\n\n' "$B" "$Z" "$B" "$Z" "$B" "$Z"
		c="$(ask "Choose:" 0)"
		case "$c" in
			1) do_install "" ;;
			2) do_update both ;;
			3) do_status ;;
			4) do_logs "$(ask "Which, node or panel? [node]" node)" ;;
			5) do_restart both ;;
			6) run_check ;;
			7) do_doctor ;;
			8) do_backup ;;
			9) do_restore "$(ask "Backup file:" "")" ;;
			10) do_uninstall ;;
			0 | q | "") return 0 ;;
			*) warn "pick a number from the list" ;;
		esac
		printf '\n'
	done
}

# SHA-256 of the archives of the one Xray-core release this Veilway runs, from the .dgst files the release publishes. Nothing else is trusted: an archive that does not match is refused, and the node checks the executable inside against its own pin before every start.
xray_pin() {
	case "$1" in
		linux-64) printf '%s' 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;;
		linux-arm64-v8a) printf '%s' 4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;;
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
				dry "install the executable into $ADDON_DIR/xray, owned by root, and the units that run it under the user veilway-xray"
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
			step "installed Xray-core $XRAY_RELEASE in $ADDON_DIR/xray"
			xray_units
			daemon_reload
			svc enable veilway-xray.socket
			svc restart veilway-xray.socket
			info "the node starts it when its config has an xray inbound; create one in the panel"
			;;
		remove)
			need_root
			svc stop veilway-xray.socket || true; svc stop veilway-xray.service || true
			svc disable veilway-xray.socket || true
			act rm -f "$UNIT_DIR/veilway-xray.socket" "$UNIT_DIR/veilway-xray.service"
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
	local args=() cmd
	while [ $# -gt 0 ]; do
		case "$1" in
			--dry-run) DRY=1 ;;
			--yes | -y) ASSUME_YES=1 ;;
			--version=*) WANT_VERSION="${1#*=}" ;;
			--version) if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then WANT_VERSION="$2"; shift; else args+=(version); fi ;;
			-h | --help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
			*) args+=("$1") ;;
		esac
		shift
	done
	[ -z "$WANT_VERSION" ] || [[ "$WANT_VERSION" =~ $TAG_RE ]] || die "that version is not a release tag"
	[[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$PANEL_PORT))" -ge 1 ] && [ "$((10#$PANEL_PORT))" -le 65535 ] || die "VEILWAY_PANEL_PORT must be a port from 1 to 65535"
	PANEL_PORT=$((10#$PANEL_PORT))
	accept_overrides
	[ "$DRY" = 1 ] && warn "dry run: nothing will be changed"
	cmd="${args[0]:-}"
	[ "${#args[@]}" -gt 0 ] && args=("${args[@]:1}")
	case "$cmd" in
		"") menu ;;
		install) header; do_install "${args[0]:-}" ;;
		update) header; do_update "${args[0]:-both}" ;;
		status) do_status ;;
		logs) do_logs "${args[0]:-node}" ;;
		restart) do_restart "${args[0]:-both}" ;;
		check | config-check) run_check ;;
		doctor) do_doctor ;;
		backup) do_backup "${args[0]:-}" ;;
		restore) do_restore "${args[0]:-}" ;;
		uninstall) header; do_uninstall ;;
		version) do_version ;;
		addon) header; do_addon "${args[0]:-}" "${args[1]:-install}" ;;
		*) die "unknown command \"$cmd\": try install, update, status, logs, restart, check, doctor, backup, restore, uninstall, version" ;;
	esac
}

main "$@"
