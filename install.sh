#!/usr/bin/env sh

# DO NOT EDIT THIS FILE DIRECTLY!
# IT IS THE COMBINATION OF 'makeinstall.sh/*.sh' and functions from
# https://github.com/client9/shlib.git

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
cat /dev/null <<EOF
------------------------------------------------------------------------
https://github.com/client9/shlib - portable posix shell functions
Public domain - http://unlicense.org
https://github.com/client9/shlib/blob/master/LICENSE.md
but credit (and pull requests) appreciated.
------------------------------------------------------------------------
EOF
is_command() {
  command -v "$1" >/dev/null
}
echoerr() {
  echo "$@" 1>&2
}
log_prefix() {
  echo "$0"
}
_logp=6
log_set_priority() {
  _logp="$1"
}
log_priority() {
  if test -z "$1"; then
    echo "$_logp"
    return
  fi
  [ "$1" -le "$_logp" ]
}
log_tag() {
  case $1 in
    0) echo "emerg" ;;
    1) echo "alert" ;;
    2) echo "crit" ;;
    3) echo "err" ;;
    4) echo "warning" ;;
    5) echo "notice" ;;
    6) echo "info" ;;
    7) echo "debug" ;;
    *) echo "$1" ;;
  esac
}
log_debug() {
  log_priority 7 || return 0
  echoerr "$(log_prefix)" "$(log_tag 7)" "$@"
}
log_info() {
  log_priority 6 || return 0
  echoerr "$(log_prefix)" "$(log_tag 6)" "$@"
}
log_err() {
  log_priority 3 || return 0
  echoerr "$(log_prefix)" "$(log_tag 3)" "$@"
}
log_crit() {
  log_priority 2 || return 0
  echoerr "$(log_prefix)" "$(log_tag 2)" "$@"
}
uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    msys*) os="windows" ;;
    mingw*) os="windows" ;;
    cygwin*) os="windows" ;;
  esac
  if [ "$os" = "sunos" ]; then
    if [ $(uname -o) == "illumos" ]; then
      os="illumos"
    else
      os="solaris"
    fi
  fi
  echo "$os"
}
uname_arch() {
  arch=$(uname -m)
  case $arch in
    x86_64) arch="amd64" ;;
    i86pc) arch="amd64" ;;
    x86) arch="386" ;;
    i686) arch="386" ;;
    i386) arch="386" ;;
    aarch64) arch="arm64" ;;
    armv5*) arch="armv5" ;;
    armv6*) arch="armv6" ;;
    armv7*) arch="armv7" ;;
  esac
  echo ${arch}
}
uname_os_check() {
  os=$(uname_os)
  case "$os" in
    darwin) return 0 ;;
    dragonfly) return 0 ;;
    freebsd) return 0 ;;
    linux) return 0 ;;
    android) return 0 ;;
    midnightbsd) return 0 ;;
    nacl) return 0 ;;
    netbsd) return 0 ;;
    openbsd) return 0 ;;
    plan9) return 0 ;;
    solaris) return 0 ;;
    illumos) return 0 ;;
    windows) return 0 ;;
  esac
  log_crit "uname_os_check '$(uname -s)' got converted to '$os' which is not a GOOS value. Please file bug at https://github.com/client9/shlib"
  return 1
}
uname_arch_check() {
  arch=$(uname_arch)
  case "$arch" in
    386) return 0 ;;
    amd64) return 0 ;;
    arm64) return 0 ;;
    armv5) return 0 ;;
    armv6) return 0 ;;
    armv7) return 0 ;;
    ppc64) return 0 ;;
    ppc64le) return 0 ;;
    mips) return 0 ;;
    mipsle) return 0 ;;
    mips64) return 0 ;;
    mips64le) return 0 ;;
    s390x) return 0 ;;
    amd64p32) return 0 ;;
  esac
  log_crit "uname_arch_check '$(uname -m)' got converted to '$arch' which is not a GOARCH value.  Please file bug report at https://github.com/client9/shlib"
  return 1
}
untar() {
  tarball=$1
  case "${tarball}" in
    *.tar.gz | *.tgz) tar -xzf "${tarball}" ;;
    *.tar) tar -xf "${tarball}" ;;
    *.zip) unzip "${tarball}" ;;
    *)
      log_err "untar unknown archive format for ${tarball}"
      return 1
      ;;
  esac
}
http_download_curl() {
  local_file=$1
  source_url=$2
  header=$3
  if [ -z "$header" ]; then
    curl -fsSL -o "$local_file" "$source_url"
  else
    curl -fsSL -H "$header" -o "$local_file" "$source_url"
  fi
}
http_download_wget() {
  local_file=$1
  source_url=$2
  header=$3
  if [ -z "$header" ]; then
    wget -q -O "$local_file" "$source_url"
  else
    wget -q --header "$header" -O "$local_file" "$source_url"
  fi
}
http_download() {
  log_debug "http_download $2"
  if is_command curl; then
    http_download_curl "$@"
    return
  elif is_command wget; then
    http_download_wget "$@"
    return
  fi
  log_crit "http_download unable to find wget or curl"
  return 1
}
http_copy() {
  tmp=$(mktemp)
  http_download "${tmp}" "$1" "$2" || return 1
  body=$(cat "$tmp")
  rm -f "${tmp}"
  echo "$body"
}
github_release() {
  owner_repo=$1
  version=$2
  test -z "$version" && version="latest"
  giturl="https://github.com/${owner_repo}/releases/${version}"
  json=$(http_copy "$giturl" "Accept:application/json")
  test -z "$json" && return 1
  version=$(echo "$json" | tr -s '\n' ' ' | sed 's/.*"tag_name":"//' | sed 's/".*//')
  test -z "$version" && return 1
  echo "$version"
}
cat /dev/null <<EOF
------------------------------------------------------------------------
End of functions from https://github.com/client9/shlib
------------------------------------------------------------------------
EOF

OS="$(uname_os)"
ARCH="$(uname_arch)"
LOGPREFIX="$GITHUB_REPO-install:"
GITHUB_DOWNLOAD="https://github.com/$OWNER_REPO/archive/refs/tags"
VENVPROMPT="${GITHUB_REPO}"
BINARIES="logtail-journal/logtail-journal.sh logtail-logcheck/logtail2"
TARBALL_FORMAT="tar.gz"
STUBBIN="jsonlogalert.sh"
RELEASE_TAG=
ARG_INSTALL_EDITABLE=
MANDIR=/usr/share/man
ETCDIR=/etc
LOGTAILDTRDIR="/usr/share/logtail/detectrotate"
SRCDIR="${SRCDIR:-}"
BINDIR="${BINDIR:-${BINDIR_DEFAULT}}"
VENVROOT="${VENVROOT:-${VENVROOT_DEFAULT}}"
parse_args()
{
  while getopts "b:edhs:t:?v:x" arg; do
    case "$arg" in
      b) BINDIR="$OPTARG" ;;
      e) ARG_INSTALL_EDITABLE=1 ;;
      d) log_set_priority 10 ;;
      h | \?) usage "$0" ;;
      s) SRCDIR="$OPTARG" ;;
      t) RELEASE_TAG="$OPTARG" ;;
      v) VENVROOT="$OPTARG" ;;
      x) set -x ;;
    esac
  done
  shift $((OPTIND - 1))
}
install_etc()
{
  srcdir="$1"
  install -d "${ETCDIR}"
  install "${srcdir}"/default-config.yaml "${ETCDIR}"/jsonlogalert.conf
  (cd /opt/jsonlogalert/default-config.d && find . -type f -exec install -D "{}" "/etc/jsonlogalert.d/{}" \;)
}
install_extras()
{
  install -d "${LOGTAILDTRDIR}"
  gzip -c man/jsonlogalert.1 >"${MANDIR}"/man1/jsonlogalert.1.gz
  log_info "Installed ${MANDIR}/man1/jsonlogalert.1.gz"
  install -m 644 logtail-logcheck/detectrotate/* "${LOGTAILDTRDIR}"/
  log_info "Installed ${LOGTAILDTRDIR}"
  gzip -c logtail-logcheck/logtail2.8 >"${MANDIR}"/man8/logtail2.8.gz
  log_info "Installed ${MANDIR}/man8/logtail2.8.gz"
}
install_stub()
{
  target="${STUBBIN##*/}" # foo.sh
  target="${target%.sh}"  # foo
  target="${BINDIR}/${target}"
  if ! test -f "$STUBBIN"; then
    log_err "${STUBBIN}: No such file"
    exit 1
  fi
  install "${STUBBIN}" "${target}"
  log_info "Installed ${target}"
  sed -E -i "s|^VENVDIR=\$|VENVDIR=\"$VENVDIR\"|" "${target}"
}
install_venv()
{
  srcdir="$1"
  arg_editable=""
  jsonlogalert_bin="${VENVDIR}"/bin/jsonlogalert
  if ! test -d "$srcdir"; then
    log_err "${srcdir}: No such directory"
    exit 1
  fi
  log_info "Creating virtual environment ${VENVDIR}"
  log_info "To activate 'source ${VENVDIR}/bin/activate'"
  python3 -m venv --system-site-packages --prompt "${VENVPROMPT}" "${VENVDIR}" 2>&1 | sed "s/^/$LOGPREFIX info > /"
  if ! test -d "$VENVDIR"; then
    log_err "${VENVDIR}: Failed to create venv directory"
    exit 1
  fi
  log_info "Installing prerequisites to ${VENVDIR}..."
  "${VENVDIR}"/bin/python -m pip install --require-virtualenv --upgrade pip 2>&1 | sed "s/^/$LOGPREFIX info > /"
  if test -z "$ARG_INSTALL_EDITABLE"; then
    log_info "Installing requirements to ${VENVDIR}..."
  else
    log_info "Installing requirements to ${VENVDIR} (editable)..."
    arg_editable="-e"
  fi
  "${VENVDIR}"/bin/python -m pip install --require-virtualenv --upgrade -r requirements.txt $arg_editable "${srcdir}" 2>&1 | sed "s/^/$LOGPREFIX info > /"
  if ! test -f "${jsonlogalert_bin}"; then
    log_err "${jsonlogalert_bin}: Failed to install"
    exit 1
  fi
  if ! "${jsonlogalert_bin}" --help >/dev/null; then
    log_err "${jsonlogalert_bin}: Installed but fails to execute"
    exit 1
  fi
}
install_binaries()
{
  srcdir=$(readlink -f "${1}")
  if ! test -d "$srcdir"; then
    log_err "${srcdir}: No such directory"
    exit 1
  fi
  test ! -d "${BINDIR}" && install -d "${BINDIR}"
  for binary in $BINARIES; do
    source="${srcdir}/${binary}"
    target="${binary##*/}" # foo.sh
    target="${target%.sh}" # foo
    target="${BINDIR}/${target}"
    if ! test -f "${source}"; then
      log_err "${source}: No such file"
      exit 1
    elif test -n "$ARG_INSTALL_EDITABLE"; then
      ln -sf "${source}" "${target}"
      log_info "Installed ${target} (editable)"
    else
      install "${source}" "${target}"
      log_info "Installed ${target}"
    fi
  done
}
install_local()
{
  srcdir=$(readlink -f "$1")
  install_venv "${srcdir}"
  install_binaries "${srcdir}"
  install_etc "${srcdir}"
  install_stub
  install_extras
}
install_release()
{
  release_ver="$1"
  tarball_untar_dir="${GITHUB_REPO}-${release_ver}"
  tarball_name="${tarball_untar_dir}.${TARBALL_FORMAT}"
  tarball_url="${GITHUB_DOWNLOAD}/${release_ver}.${TARBALL_FORMAT}"
  # mktemp will create a subdirectory of '$TMPDIR' if set
  tmpdir=$(mktemp -d)
  trap 'rm -rf -- "${tmpdir}"' EXIT
  if ! test -d "${tmpdir}"; then
    log_err "${tmpdir}: No such directory"
    exit 1
  fi
  log_debug "downloading files into ${tmpdir}"
  http_download "${tmpdir}/${tarball_name}" "${tarball_url}"
  (cd "${tmpdir}" && untar "${tarball_name}")
  install_local "${tmpdir}/${tarball_untar_dir}"
}
tag_to_version()
{
  release_tag="$1"
  if [ -z "${release_tag}" ]; then
    log_debug "Checking GitHub for latest release tag"
    release_tag="latest"
  else
    log_debug "Checking GitHub for release tag '${release_tag}'"
  fi
  realtag=$(github_release "$OWNER_REPO" "${release_tag}") && true
  if test -z "$realtag"; then
    log_err "Unable to find release tag '${release_tag}'; see https://github.com/$OWNER_REPO/releases"
    exit 1
  fi
  release_ver=${realtag#v} # remove 'v' prefix
  if [ "${release_tag}" = "latest" ]; then
    log_info "Latest release is version ${release_ver}"
  fi
  echo "${realtag}"
}
log_prefix()
{
  echo "$LOGPREFIX"
}
main()
{
  uname_os_check "$OS"
  uname_arch_check "$ARCH"
  parse_args "$@"
  VENVDIR="${VENVROOT}/${GITHUB_REPO}"
  if test -n "${TMPDIR}"; then
    # mktemp fails if '$TMPDIR' is set but does not exist
    if ! test -d "${TMPDIR}"; then
      log_err "TMPDIR=${TMPDIR}: No such directory"
      exit 1
    fi
  fi
  if ! test -w "$BINDIR"; then
    log_err "${BINDIR}: Write permission denied"
    exit 1
  fi
  if test -z "$SRCDIR"; then
    release_ver=$(tag_to_version "${RELEASE_TAG}")
    install_release "${release_ver}"
  else
    install_local "${SRCDIR}"
  fi
}
main "$@"
