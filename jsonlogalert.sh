#!/usr/bin/env sh

# systemd services *will not* run scripts that do not have the appropriate SELinux context.
# This undoubtably means we cannot run 'jsonlogalert' directly from the virtual environment.
# This script is a stub that can be placed in a directory where it can inherit the required context.

set -u

# 'install.sh' hard-codes VENVDIR to the virtual environment path;
# Defaulting to VIRTUAL_ENV is a dev environment fallback.
VIRTUAL_ENV="${VIRTUAL_ENV:-}"
VENVDIR=
VENVDIR="${VENVDIR:-$VIRTUAL_ENV}"
SCRIPT="$VENVDIR"/bin/jsonlogalert
SYSTEMD_ETC=/etc/systemd/system

# Print usage and exit
usage()
{
	cat <<EOF
Try 'jsonlogalert --help' for more help.

USAGE
  jsonlogalert systemd COMMAND
  jsonlogalert [OPTIONS] [LOGFILE]...

SYNOPSIS
  systemd      Convenient way to manage systemd service, timer and path units
               with the prefix 'jsonlogalert-'.

COMMANDS
  list         List timer and path units.
  enable       Enable and start timer and path units.
  disable      Disable and stop timer and path units.
  install DIR  Copy units from DIR to '$SYSTEMD_ETC'.
  uninstall    Remove units from '$SYSTEMD_ETC'.

OPTIONS
  -h    Show this help and exit
EOF
	exit 2
}

# Write to stderr; use `echo` for stdout.
msg()
{
	echo >&2 "$@"
}

# Write to stderr and exit non-zero
die()
{
	message="${1:-}"
	[ -z "$message" ] || msg "$message"
	exit 1
}

###############################################################################
# main

# Parse command line options
while getopts ":h-:" opt; do
	case "$opt" in
		h) usage ;;
        *);;
	esac
done

# Convenience option to manage systemd timer and path units.
if [ -n "${1:-}" ] && [ "$1" = "systemd" ]; then
    systemd_cmd="${2:-}"
    systemd_opt="${3:-}"

    if [ "$systemd_cmd" = "list" ]; then
        find "$SYSTEMD_ETC" -maxdepth 1 -regextype egrep -regex '.*/jsonlogalert-[^.]+\.(path|timer)' -printf "%f\n"
    elif [ "$systemd_cmd" = "enable" ] || [ "$systemd_cmd" = "disable" ]; then
        find "$SYSTEMD_ETC" -maxdepth 1 -regextype egrep -regex '.*/jsonlogalert-[^.]+\.(path|timer)' -printf "%f\n" | xargs --no-run-if-empty --verbose systemctl --quiet --no-reload "$systemd_cmd" --now
        systemctl daemon-reload
    elif [ "$systemd_cmd" = "uninstall" ]; then
        find "$SYSTEMD_ETC" -maxdepth 1 -regextype egrep -regex '.*/jsonlogalert-[^.]+\.(path|timer|service)' -delete
    elif [ "$systemd_cmd" = "install" ] && [ -n "$systemd_opt" ] && [ -d "$systemd_opt" ]; then
        find "$systemd_opt" -maxdepth 1 -regextype egrep -regex '.*/jsonlogalert-[^.]+\.(path|timer|service)' -print0 | xargs -0 --no-run-if-empty --verbose cp -t "$SYSTEMD_ETC"
    else
        usage
    fi

    exit 0
fi

[ -n "$VENVDIR" ] || die "This script is a stub; it is not standalone until install.sh copies it; you can also set VIRTUAL_ENV"
[ -d "$VENVDIR" ] || die "$VENVDIR: No such directory."
[ -f "$SCRIPT"  ] || die "$SCRIPT: No such file."

exec "$SCRIPT" "$@"
