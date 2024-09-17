#!/usr/bin/env bash
#
# Print systemd journal lines that have not been read.
# Analogous to logtail2 (https://linux.die.net/man/8/logtail2) but for systemd journal.
#
# Copyright (c) 2024 Lance Lovette
# All rights reserved.
# Licensed under the BSD License.
# See the file LICENSE.md for the full license text.

set -eu

ARG_JSON_FORMAT="json"
ARG_SHOW_COMMAND=false
ARG_SINCE_ALL=false
ARG_SINCE_BOOT=false
ARG_SINCE_TODAY=false
ARG_DRY_RUN=false
ARG_CURSOR_FILE="/var/lib/misc/logtail-journal-cursor"
ARG_JOURNAL_DIR=
RESET_CURSOR=false

######################################################################

function usage()
{
	cat <<EOF
Print systemd journal lines that have not been read.

USAGE
  logtail-journal [OPTIONS]

OPTIONS
  -A        Print entire log (ignores cursor).
  -b        Print lines since last boot (ignores cursor).
  -d        Print journalctl command line and exit.
  -D DIR    Operate on the specified journal directory.
  -h        Display this help and exit.
  -o FILE   Cursor file path; default is $ARG_CURSOR_FILE.
  -p        Pretty print JSON output.
  -r        Print lines since today (ignores cursor).
  -t        Test mode; do not update cursor.

EOF
	exit 2
}

# Write to stderr; use `echo` for stdout.
function msg()
{
	echo >&2 "$@"
}

# Write to stderr and exit non-zero
function die()
{
	local message="${1:-}"
	[ -z "$message" ] || msg "$message"
	exit 1
}

######################################################################

# Parse command line options
while getopts "AbdD:ho:prt?" opt; do
	case "$opt" in
		A) ARG_SINCE_ALL=true ;;
		b) ARG_SINCE_BOOT=true ;;
		d) ARG_SHOW_COMMAND=true ;;
		D) ARG_JOURNAL_DIR="$OPTARG" ;;
		h | \?) usage ;;
		o) ARG_CURSOR_FILE="$OPTARG" ;;
		p) ARG_JSON_FORMAT="json-pretty" ;;
		r) ARG_SINCE_TODAY=true ;;
		t) ARG_DRY_RUN=true ;;
	esac
done

shift $((OPTIND - 1))

declare -a journalctl_args
journalctl_args+=("--quiet")
journalctl_args+=("--no-pager")
journalctl_args+=("--no-tail")
journalctl_args+=("--output=$ARG_JSON_FORMAT")

# Show all fields in full, even if they include unprintable characters or are very long.
# (json output sets fields larger than 4096 bytes to `null` by default)
journalctl_args+=("--all")

# Default first run to -r
if [ ! -f "$ARG_CURSOR_FILE" ] || [ ! -s "$ARG_CURSOR_FILE" ]; then
	ARG_SINCE_TODAY=true
fi

if [ "$ARG_SINCE_ALL" = true ]; then
	RESET_CURSOR=true
elif [ "$ARG_SINCE_BOOT" = true ]; then
	journalctl_args+=("--boot")
	RESET_CURSOR=true
elif [ "$ARG_SINCE_TODAY" = true ]; then
	journalctl_args+=("--since=today")
	RESET_CURSOR=true
fi

if [ "$ARG_DRY_RUN" = false ]; then
	if [ "$RESET_CURSOR" = true ]; then
		: >"$ARG_CURSOR_FILE"
	fi

	[ -f "$ARG_CURSOR_FILE" ] || die "$ARG_CURSOR_FILE: No such cursor file"

	journalctl_args+=("--cursor-file=$ARG_CURSOR_FILE")
else
	if [ "$RESET_CURSOR" = false ] && [ -f "$ARG_CURSOR_FILE" ] && [ -s "$ARG_CURSOR_FILE" ]; then
		journalctl_args+=("--cursor=$(<"$ARG_CURSOR_FILE")")
	fi
fi

if [ -n "$ARG_JOURNAL_DIR" ]; then
	[ -d "$ARG_JOURNAL_DIR" ] || die "$ARG_JOURNAL_DIR: No such directory"

	journalctl_args+=("--directory=$ARG_JOURNAL_DIR")
fi

if [ "$ARG_SHOW_COMMAND" = true ]; then
	echo journalctl "${journalctl_args[@]}"
	exit 0
fi

exec journalctl "${journalctl_args[@]}"
