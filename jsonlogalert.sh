#!/usr/bin/env sh

# systemd services *will not* run scripts that do not have the appropriate SELinux context.
# This undoubtably means we cannot run 'jsonlogalert' directly from the virtual environment.
# This script is a stub that can be placed in a directory where it can inherit the required context.

VENVDIR=
SCRIPT="$VENVDIR/bin/jsonlogalert"

if test -z "$VENVDIR"; then
    echo "This script is a stub; VENVDIR must be set when installed"
    exit 1
fi

if ! test -d "$VENVDIR"; then
    echo "$VENVDIR: No such directory"
    exit 1
fi

if ! test -f "$SCRIPT"; then
    echo "$SCRIPT: No such file"
    exit 1
fi

exec "$SCRIPT" "$@"
