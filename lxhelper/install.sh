#!/bin/bash
# shellcheck disable=SC2015

umask 0077
export LANG=C
export LC_ALL=C

declare -r lxdf_ver=1.44
declare -r lxdh_ver=1.07
silent=no
tmpdir="${TEMP:=/tmp}"

index_url="${REMOTE_URI:-https://oss.help/scripts/lxc/lxhelper/.list}"
list_name=$(basename "${index_url}")
script_name="lxhelper"
script_path="/usr/local/sbin"
func_name="lxd-functions.sh"
func_path="/usr/local/include/osshelp"
yq_bin='yq'
yq_bin_path='/usr/local/bin'
minio_client_bin='minio-client'
minio_client_path='/usr/local/sbin'
shacmd=$(command -v sha256sum || command -v gsha256sum 2>/dev/null)
err=0

function show_notice() { test "${silent}" != "yes" && echo -e "[NOTICE] ${*}"; return 0; }
function show_error() { echo -e "[ERROR] ${*}" >&2;  err=1; return 1; }

function fetch_files() {
  cd "${1}" && \
    {
      wget -q -P "${1}" "${index_url}" && \
      wget -q -i "${1}/${list_name}" -P "${1}"
    } && \
      ${shacmd} -c --status SHA256SUMS 2> /dev/null || {
        show_error "Something went wrong, checksums of downloaded files mismatch."
        ${shacmd} -c "${1}/SHA256SUMS"
        return 1
      }
}

function install_files() {
  test -d "${script_path}" || mkdir "${script_path}"
  cd "${script_path}" && \
    mv "${tmp_dir}/${script_name}" "${script_path}/${script_name}" && \
      chmod 700 "${script_path}/${script_name}"

  test -d "${func_path}" || mkdir "${func_path}"
  cd "${func_path}" && \
    mv "${tmp_dir}/${func_name}" "${func_path}/${func_name}" && \
      chmod 600 "${func_path}/${func_name}"

  test -d "${minio_client_path}" || mkdir "${minio_client_path}"
  cd "${minio_client_path}" && \
    mv "${tmp_dir}/${minio_client_bin}" "${minio_client_path}/${minio_client_bin}" && \
      chmod 755 "${minio_client_path}/${minio_client_bin}"
}

test "$(id -u)" != "0" && { show_error "Sorry, but you must run this script as root."; exit 1; }

tmp_dir="${tmpdir}/lxd-functions.$$"
mkdir -p "${tmp_dir}" && \
  fetch_files "${tmp_dir}" && \
    install_files "${tmp_dir}" && \
      {
        test -x "${yq_bin_path}/${yq_bin}" || curl -s https://oss.help/scripts/tools/yq/install.sh | bash
        show_notice "Minio-client was installed to ${minio_client_path}."
        show_notice "Library lxd-functions.sh (v${lxdf_ver}) was installed to $func_path."
        show_notice "Script lxhelper (v${lxdh_ver}) was installed to $script_path."
      }
test -d "${tmp_dir}" && rm -rf "${tmp_dir}"
test "${err}" -eq 1 && { show_error "Installation failed."; }
exit "${err}"
