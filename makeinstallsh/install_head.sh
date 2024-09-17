#!/usr/bin/env sh

set -e

GITHUB_OWNER="lovette"
GITHUB_REPO="jsonlogalert"
OWNER_REPO="$GITHUB_OWNER/$GITHUB_REPO"
VENVROOT_DEFAULT="${HOME}/.venv"
BINDIR_DEFAULT="/usr/local/bin"

usage()
{
  this=$1
  cat <<EOF
Download and install binaries for ${OWNER_REPO}.

USAGE
  $this [OPTIONS]

OPTIONS
  -b BINDIR    Install binaries to directory BINDIR; defaults to '${BINDIR_DEFAULT}'.
  -d           Enable debug logging.
  -e           Install in editable mode (i.e. "develop mode") from a local project path.
  -h           Show this help and exit.
  -s SRCDIR    Install from local project path SRCDIR; defaults to latest GitHub release.
  -t TAG       Install version tag; defaults to 'latest' (from https://github.com/$OWNER_REPO/releases).
  -v VENVROOT  Create Python environment in VENVROOT; defaults to '${VENVROOT_DEFAULT}'.

ENVIRONMENT VARIABLES
  BINDIR       Equivalent to specifying the -b option.
  SRCDIR       Equivalent to specifying the -s option.
  VENVDIR      Equivalent to specifying the -v option.
  TMPDIR       If set, create temporary directory relative to TMPDIR; default is '/tmp'.

EOF
  exit 2
}
