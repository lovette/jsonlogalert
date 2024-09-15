#!/usr/bin/env sh

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

# Can set with OPTIONS or environment variables
SRCDIR="${SRCDIR:-}"
BINDIR="${BINDIR:-${BINDIR_DEFAULT}}"
VENVROOT="${VENVROOT:-${VENVROOT_DEFAULT}}"

# ------------------------------------------------------------------------
# BEGIN MAIN

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

# use in logging routines
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

# END MAIN
# ------------------------------------------------------------------------
