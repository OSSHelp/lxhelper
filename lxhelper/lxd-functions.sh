#!/bin/bash

## OSSHelp lxd functions library.
# shellcheck disable=SC2207
# shellcheck disable=SC2015
# shellcheck disable=SC2016
# shellcheck disable=SC1090

## TODO:
## - divide proceed_section() and download_image_for_container() to separate functions

lxdf_ver=1.44
yml_current_ver=2
yml_deprecated_ver=1
min_lxd_ver='2.15'
cur_lxd_ver="$(lxc --version)"
lxd_versions=("${min_lxd_ver}" "${cur_lxd_ver}")

lxc_cmd=$(command -v lxc)
curl_cmd=$(command -v curl)
yq_cmd=$(command -v yq)
mc_cmd=$(command -v minio-client)
pytest_script=$(command -v py.test)

uuid_url="https://oss.help/uuid"
force_ua="lxc-helper/${lxdf_ver} (${LC_HOST:--}/${our_uuid}/${LC_SHIFT:--})"
our_uuid=$(test -s /var/backups/uuid && cat /var/backups/uuid || curl --silent --user-agent "${force_ua}" ${uuid_url} | tee /var/backups/uuid)
download_retry=3
silent='no'
container_wait=60 # seconds, given to container for booting

containers_data_dir="/mnt/data/containers"
images_dir="/mnt/data/images"
yml_dir="/usr/local/etc/lxc"
lxhelper_cfg="${yml_dir}/helper.cfg"
profiles_dir="/usr/local/osshelp/profiles"

log_file=/var/log/${0##*/}.log
exec &> >(tee -a "${log_file}")

function have_testinfra() { test -x "${pytest_script}"; }
function have_pylxd() { python3 -c 'import pkgutil; exit(not pkgutil.find_loader("pylxd"))' >/dev/null 2>&1; }
function show_notice() {
  local -r log_date=$(date '+%Y/%m/%d %H:%M:%S')
  test "${silent}" != "yes" && echo -e "[NOTICE ${log_date}] ${*}"; return 0;
}
function show_warning() {
  local -r log_date=$(date '+%Y/%m/%d %H:%M:%S')
  test "${silent}" != "yes" && echo -e "[WARNING ${log_date}] ${*}"; return 0;
}
function show_error() {
  local -r log_date=$(date '+%Y/%m/%d %H:%M:%S')
  echo -e "[ERROR ${log_date}] ${*}" >&2; return 1;
}
function show_fatal() {
  local -r log_date=$(date '+%Y/%m/%d %H:%M:%S')
  echo -e "[FATAL ${log_date}] ${*}" >&2; exit 1;
}

function check_lxd_version() {
  show_notice "Checking LXD version..."
  grep -qP '\d+\.\d+(\.\d+)?' <<< "${cur_lxd_ver}" || { show_error "Can't get version of LXD, is it installed?"; exit 1; }
  test "$(printf '%s\n' "${lxd_versions[@]}" | sort -rV | tail -1)" = "${min_lxd_ver}" || { show_error "LXD version is lower than 2.15, you need update it first!"; exit 1; }
}

function container_exists() {
  local container_name="${1}"
  lxc info "${container_name}" > /dev/null 2>&1
}

function container_is_running() {
  local container_name="${1}"
  lxc info "${container_name}" | grep -q 'Status: Running'
}

function check_cmd_in_container() {
  local container_name="${1}"; local command="${2}"
  lxc exec "${container_name}" -- /bin/bash -c 'command -v $0' "${command}" >/dev/null 2>&1
}

function run_cmds_in_container() {
  local container_name="${1}"; local commands="${2}"
  lxc exec "${container_name}" -- /bin/bash -c "${commands}"
}

function get_container_os() {
  local container_name="${1}"
  check_cmd_in_container "${container_name}" lsb_release || {
    show_error "Cannot determine OS, lsb_release not found. Install package lsb-release or redhat-lsb-core."
    return 1
  }
  run_cmds_in_container "${container_name}" 'lsb_release -si' 2>/dev/null
}

function wait_for_container_to_boot() {
  local container_name="${1}"; local err=1
  container_is_running "${container_name}" && {
    show_notice "Waiting up to ${container_wait}s for container to fully boot"
    lxc exec "${container_name}" -- bash -c 'command -v systemctl >/dev/null' || \
      return "${err}"
    i=${container_wait}
    while [ "${i}" -gt 0 ]; do
      system_state=$(lxc exec "${container_name}" -- bash -c 'systemctl is-system-running 2>/dev/null')
      test "${system_state}" == "running" -o "${system_state}" == "degraded" && {
        test "${system_state}" == "running" && \
          err=0
        break
      }
      sleep 1
      i=$((i-1))
    done
  }
  return "${err}"
}

function testinfra_custom_delay {
  container_testinfra_delay_value=$(get_value "containers.${container_section}.testinfra.delay" "${yml_localpath}")
  container_testinfra_profile_delay_value=$(get_value "containers.${container_section}.profiles.${selected_profile:-default}.testinfra.delay" "${yml_localpath}")
  test -n "${container_testinfra_profile_delay_value}" && {
    show_notice "Waiting for ${container_testinfra_profile_delay_value}s before running testinfra tests..."
    sleep "${container_testinfra_profile_delay_value}"
  }
  test -n "${container_testinfra_delay_value}" && {
    test -z "${container_testinfra_profile_delay_value}" && {
      show_notice "Waiting for ${container_testinfra_delay_value}s before running testinfra tests..."
      sleep "${container_testinfra_delay_value}"
    }
  }
}

function image_exists() {
  local image_alias="${1}"
  lxc image info "${image_alias}" > /dev/null 2>&1
}

function yml_contains_limits_for_container() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  local err=0; local container_limit_subkeys; local memory_limit_found=0; local cpu_limit_found=0
  container_limit_subkeys=($(get_keys "containers.${container_section}.limits" "${yml_localpath}"))
  test "${#container_limit_subkeys[@]}" -gt "0" && {
    for subkey in "${container_limit_subkeys[@]}"; do
      [[ "${subkey}" =~ ^cpu(\..+)?$ ]] && { cpu_limit_found=1; continue; }
      [[ "${subkey}" =~ ^memory(\..+)?$ ]] && memory_limit_found=1
    done
  }
  test "${cpu_limit_found}" == "1" || \
    { show_warning "You should set CPU limit for container in YML-config! (see https://oss.help/kb2459)"; err=1; }
  test "${memory_limit_found}" == "1" || \
    { show_warning "You should set memory limit for container in YML-config! (see https://oss.help/kb2459)"; err=1; }
  return "${err}"
}

function yml_is_valid() {
  target_yml=${1}
  test -r "${target_yml}" && {
    ${yq_cmd} r "${target_yml}" >/dev/null 2>&1 || show_fatal "YML-config ${target_yml} is not parseable via yq, you need to check it!"
    ${yq_cmd} r "${target_yml}" 2>&1 | grep -qE ':\snull$' && \
      show_warning "YML-config contains keys with \"null\" values, you should check and fix them!"
  }
}

function download_file() {
  local target_url="${1}"; local target_file="${2}"; local transport="${3:-http}"; local -r target_dir=$(dirname "${target_file}")
  local error_code_received=0; local proto; local user; local password

  test -d "${target_dir}" || { show_notice "Creating directory ${target_dir}"; mkdir -p "${target_dir}"; }
  test -f "${target_file}.info" && local time_opts="${target_file}.info"

  test "$(get_value download "${yml_localpath}" none)" != "none" && {
    proto=$(get_value download.proto "${yml_localpath}" http)
    user=$(get_value download.user "${yml_localpath}" none)
    password=$(get_value download.password "${yml_localpath}" none)

    test "${user}" == none -o "${password}" == none && {
      show_error "No valid credentials found in download section of YML-config!"
      return 1
    }
  }

  # we're tryting to download YML first time and we can use "transport" option from CLI
  test -z "${proto}" -a -n "${transport}" && \
    proto="${transport}"

  show_notice "Downloading ${target_url} to ${target_file} (over ${proto})"

  test "${proto}" == "http" && {
    test -n "${user}" && error_code=$( $curl_cmd -u "${user}:${password}" --silent --remote-time --retry ${download_retry} --user-agent "${force_ua}" --compressed --location --fail --time-cond "${time_opts:-1970 Jan 1}" --write-out '%{http_code}' --output "${target_file}" "${target_url}" )
    test -z "${user}" && error_code=$( $curl_cmd --silent --remote-time --retry ${download_retry} --user-agent "${force_ua}" --compressed --location --fail --time-cond "${time_opts:-1970 Jan 1}" --write-out '%{http_code}' --output "${target_file}" "${target_url}" )
    error_code_received=1
  }

  test "${proto}" == "s3" && {
    # we're tryting to download YML first time and we have username:password specified in URL
    test -z "${user}" -a -z "${password}" && {
      user=$( sed -rn 's|^\w+://(\w+):\w+@.+|\1|p' <<< "${target_url}" )
      password=$( sed -rn 's|^\w+://\w+:(\w+)@.+|\1|p' <<< "${target_url}" )
    }
    download_file_from_s3 "${target_url}" "${target_file}" "${user}" "${password}" && \
      return 0 || return 1
  }

  test "${error_code_received}" != 1 && \
    error_code=$( $curl_cmd --silent --remote-time --retry ${download_retry} --user-agent "${force_ua}" --compressed --location --fail --time-cond "${time_opts:-1970 Jan 1}" --write-out '%{http_code}' --output "${target_file}" "${target_url}" )
  test "${error_code:-000}" -eq 200 && {
    { echo "date: $(date)"; echo "url: ${target_url}"; echo "file: ${target_file}"; } > "${target_file}.info"
    touch -r "${target_file}" "${target_file}.info"
  }
  test "${error_code:-000}" -eq 200 -o "${error_code:-000}" -eq 304 && return 0 || return 1
}

function download_file_from_s3() {
  local target_url="${1}"; local target_file="${2}"
  local user="${3}"; local password="${4}"; local endpoint
  local err=0

  test -x "${mc_cmd}" || { show_error "No minio-client binary found, can't download file!"; return 1; }

  # getting the endpoint and source file from received url, exporting the var for minio-client
  endpoint=$(sed -r 's|.+//(.+@)?||;s|/.+||' <<< "${target_url}")
  source_file=$(sed -r 's|.+//(.+@)?||;s|[^/]*||;s|^/||' <<< "${target_url}")

  test -n "${user}" -a -n "${password}" && \
    export MC_HOST_LXHELPER="https://${user}:${password}@${endpoint}"
  test -z "${user}" -a -z "${password}" && \
    export MC_HOST_LXHELPER="https://${endpoint}"

  # actions with date below are for avoiding image redownloading if modification date of file in bucket was not changed since last download
  source_date=$(timeout 10 "${mc_cmd}" stat "LXHELPER/${source_file}" | grep ^Date | sed -r 's|.+: ||')
  # we can't access required file and shouldn't proceed forward
  test -z "${source_date}" && {
    show_error "Can't get the date of last modification for ${target_url}"
    return 1;
  }
  source_timestamp=$(date --date="${source_date}" +"%s")
  test -f "${target_file}.info" && {
    recorded_date=$(grep source_modification_date "${target_file}.info" | sed -r 's|.+: ||')
    recorded_timestamp=$(date --date="${recorded_date}" +"%s")
    # returning 0 if dates are the same
    test "${source_timestamp}" == "${recorded_timestamp}" && \
      test -f "${target_file}" -a -s "${target_file}" && {
        show_notice "File wasn't changed in S3-bucket, skipping download"
        return 0
      }
  }

  # downloading file
  $mc_cmd -q cp "LXHELPER/${source_file}" "${target_file}" >/dev/null || err=1
  # updating the .info file on download success
  test "${err}" == 0 && \
    { echo "date: $(date)"; echo "url: ${target_url}"; echo "file: ${target_file}"; echo "source_modification_date: ${source_date}"; } > "${target_file}.info"
  test "${err}" -ne 0 && { show_error "Error on downloading ${target_url}";}
  return "${err}"
}

function get_lxd_value() {
  local container_name="${1}"; local key_name="${2}"; local default_value="${3}"
  key_value=$(lxc config show "${container_name}" 2>/dev/null | $yq_cmd r - "${key_name}" 2>/dev/null)
  test -n "${key_value}" -a "${key_value}" != "null" && echo -n "${key_value}"
  test -z "${key_value}" -o "${key_value}" = "null" && echo -n "${default_value}"
}

function key_exists_in_yml() {
  local yml_path="${1}"; local key_name="${2}"; local key_does_not_exist=1; local value; local error_code
  test -r "${yml_path}" && {
    value=$(${yq_cmd} r "${yml_path}" "${key_name}" 2>/dev/null)
    error_code="${?}"
    test "${error_code}" -ne "0" && return "${error_code}"
    test "${value}" != "null" && key_does_not_exist=0
  }
  return "${key_does_not_exist}"
}

function get_value() {
  local key_name="${1}"; local file_name="${2}"; local default_value="${3}"
  key_value=$($yq_cmd r "${file_name}" "${key_name}" 2>/dev/null)
  # reset key_value because something went wrong and it's useless
  test "${?}" -ne 0 && key_value=""
  test -n "${key_value}" -a "${key_value}" != "null" && echo -n "${key_value}"
  test -z "${key_value}" -o "${key_value}" = "null" && echo -n "${default_value}"
}

function get_keys() {
  local key_name="${1}"; local file_name="${2}"
  keys_list=$($yq_cmd r "${file_name}" "${key_name}" 2>/dev/null)
  # reset keys_list because something went wrong and it's useless
  test "${?}" -ne 0 && keys_list=""
  echo "${keys_list}" | sed -rn 's|^(\S+):.*|\1|p'
}

function check_and_generate_config() {
  test -d "${yml_dir}" || mkdir -p "${yml_dir}"
  test -f "${lxhelper_cfg}" && {
    bad_lines=$(grep -cvE '^[a-zA-Z0-9_]+=\"?[a-zA-Z0-9_\.-]+\"?\s*$' "${lxhelper_cfg}")
    test "${bad_lines}" -gt "0" && { show_error "There is something wrong with ${lxhelper_cfg}, fix it!"; exit 1; }
    show_notice "Using vars from ${lxhelper_cfg}"
    source "${lxhelper_cfg}"
    return
  }
  test -f "${lxhelper_cfg}" || {
    show_notice "Generating ${lxhelper_cfg}"
    test -z "${LC_HOST}" || echo "our_hostname=${LC_HOST}" > "${lxhelper_cfg}"
    test -z "${LC_HOST}" && echo "our_hostname=$(hostname -f)" > "${lxhelper_cfg}"
    test -f "${lxhelper_cfg}" && {
      show_notice "Using vars from ${lxhelper_cfg}"
      source "${lxhelper_cfg}"
    }
  }
}

function clean_container() {
  local container_name="${1}";
  container_is_running "${container_name}" && {
    show_notice "Cleaning container ${container_name}"
    local os; os="$(get_container_os "${container_name}")" || {
      show_notice "Doing only OS-independent cleaning then..."
    }
    case ${os,,} in
      ubuntu|debian)
        show_notice "${os} detected, cleaning apt-related stuff"
        {
          echo 'apt-get -q autoremove -y > /dev/null'
          echo 'apt-get clean'
          echo 'find /var/lib/apt/lists/ -type f -delete'
        } | lxc exec "${container_name}" -- bash -s
        ;;
      centos)
        show_notice "${os} detected, cleaning yum-related stuff"
        {
          echo 'yum autoremove -y -q > /dev/null'
          echo 'yum clean all -q'
        } | lxc exec "${container_name}" -- bash -s
      ;;
    esac
    {
      echo 'find /var/log/ -type f -iname "*.gz" -delete'
      echo 'find /var/log/ -type f -iname "*.?" -delete'
      echo 'find /var/log/ -type f -iname "wtmp\.*" -delete'
      echo 'find /var/log/ -type f -iname "lastlog\.*" -delete'
      echo 'echo -n > /var/log/wtmp'
      echo 'echo -n > /var/log/lastlog'
      echo 'find /root/ -maxdepth 1 -type f -iname "\.*_history" -delete'
    } | lxc exec "${container_name}" -- bash -s
    return 0
  }
  show_error "Container ${container_name} is not running. Skipping the cleaning part."
}

function create_container() {
  local container_name="${1}"; local container_template="${2}";
  found_by_name=$(lxc list "${container_name}" -c n --format csv | grep -c "^${container_name}$")
  container_protection=$(get_lxd_value "${container_name}" "config.user\.protected" "false")
  container_redeployable=$(get_lxd_value "${container_name}" "config.[user.deployed_from]" "none")
  #show_notice "Container protection set to ${container_protection}"
  test "${found_by_name:-0}" -eq 1 -a "${container_protection:-false}" = "true" -a "${force_mode:-false}" = "false" && show_fatal "Can't create the container \"${container_name}\", it already exists and is protected."
  test "${found_by_name:-0}" -eq 1 -a "${container_redeployable:-none}" = "none" -a "${force_mode:-false}" = "false" && show_fatal "Container \"${container_name}\" already exists and is not redeployable via lxhelper (manually created?)."
  test "${found_by_name:-0}" -eq 1 && {
    show_notice "Deleting existing container ${container_name} (protection=${container_protection},force=${force_mode:-false})"
    lxc delete -f "${container_name}"
  }
  show_notice "Creating container ${container_name} from ${container_template}"
  lxc init "${container_template}" "${container_name}" >/dev/null
}

function mount_directories_to_container() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"

  # it's main devices section in YML
  devices_set_main="containers.${container_section}.devices"
  # assotiative array for devices. KEYNAME is a device (mount) name and it's VALUE shows which section of YML (main/profile) must be used for a specific device
  declare -A container_devices
  # save devices from main section
  for device in $(get_keys "${devices_set_main}" "${yml_localpath}"); do
    container_devices[${device}]=main
  done

  test "${selected_profile:-none}" != none && {
    # it's device section of selected profile
    devices_set_profile="containers.${container_section}.profiles.${selected_profile}.devices"
    # copy devices names marking them as 'profile', overwriting previous records
    for device in $(get_keys "${devices_set_profile}" "${yml_localpath}"); do
      container_devices[${device}]=profile
    done
  }

  local -r lxd_subuid=$(grep -P -m 1 '^lxd:' /etc/subuid | cut -d ':' -f 2)
  local -r lxd_subgid=$(grep -P -m 1 '^lxd:' /etc/subgid | cut -d ':' -f 2)

  local container_is_priveleged=0
  container_priveleged_mode=$(get_value "containers.${container_section}.privileged" "${yml_localpath}" "false")
  test "${container_priveleged_mode}" = "true" -o "${container_priveleged_mode}" = "True" -o "${container_priveleged_mode}" == "1" && \
    container_is_priveleged=1

  for container_device in "${!container_devices[@]}"; do
    devices_set="${devices_set_main}"
    test "${selected_profile:-none}" != none && test "${container_devices[${container_device}]}" == 'profile' && devices_set="${devices_set_profile}"
    source_dir=$(get_value "${devices_set}.${container_device}.source" "${yml_localpath}")
    target_dir=$(get_value "${devices_set}.${container_device}.path" "${yml_localpath}")
    target_uid=$(get_value "${devices_set}.${container_device}.uid" "${yml_localpath}")
    target_gid=$(get_value "${devices_set}.${container_device}.gid" "${yml_localpath}")
    target_acl=$(get_value "${devices_set}.${container_device}.mode" "${yml_localpath}")

    # if raw.idmap is used
    target_uid_base=$(get_value "${devices_set}.${container_device}.uid_base" "${yml_localpath}")
    target_gid_base=$(get_value "${devices_set}.${container_device}.gid_base" "${yml_localpath}")

    local target_dir_created="false";
    local resulting_acl=${target_acl:-750}
    local resulting_uid=${target_uid:-0}
    local resulting_gid=${target_gid:-0}

    test -d "${source_dir}" || { mkdir -p "${source_dir}" && target_dir_created="true"; }
    test "${container_is_priveleged}" == 0 && {
      test -n "${target_uid_base}" \
        && resulting_uid=$(( ${target_uid_base:-100000} + ${target_uid:-0} )) \
        || resulting_uid=$(( ${lxd_subuid:-100000} + ${target_uid:-0} ))
      test -n "${target_gid_base}" \
        && resulting_gid=$(( ${target_gid_base:-100000} + ${target_gid:-0} )) \
        || resulting_gid=$(( ${lxd_subgid:-100000} + ${target_gid:-0} ))
    }
    test -n "${target_uid}" && test -n "${target_gid}" && test -n "${target_acl}" && {
      show_notice "Changing owner: ${resulting_uid}, group: ${resulting_gid}, permission: ${resulting_acl} for ${target_dir}"
      chown "${resulting_uid}:${resulting_gid}" "${source_dir}"
      chmod "${resulting_acl}" "${source_dir}"
    }
    test "${target_dir_created}" = "true" -a -z "${target_uid}" && test -z "${target_gid}" && test -z "${target_acl}" && {
      show_notice "Changing owner: ${resulting_uid}, group: ${resulting_gid}, permission: ${resulting_acl} for ${target_dir}"
      chown "${resulting_uid}:${resulting_gid}" "${source_dir}"
      chmod "${resulting_acl}" "${source_dir}"
    }

    show_notice "Mounting ${source_dir} as ${target_dir} in ${container_name}"
    lxc config device add "${container_name}" "${container_device}" disk source="${source_dir}" path="${target_dir}" >/dev/null || show_fatal "Failed to add ${source_dir} as ${target_dir} into ${container_name}"
    set_device_resource_limits "${container_name}" "${container_section}" "${yml_localpath}" "${container_device}"
  done
}

function set_network_parameters_for_container() {
  local container_name="${1}"; local container_section="${2}"
  local yml_localpath="${3}"; local err=0
  main_network_section="containers.${container_section}.network"
  profile_network_section="containers.${container_section}.profiles.${selected_profile:-default}.network"

  # preparing interfaces list
  main_interfaces=($(get_keys "${main_network_section}" "${yml_localpath}"))
  profile_interfaces=($(get_keys "${profile_network_section}" "${yml_localpath}"))
  container_interfaces=( "${main_interfaces[@]}" "${profile_interfaces[@]}" )

  test "${#container_interfaces[@]}" -gt 0 && {
    for container_interface in $(printf '%s\n' "${container_interfaces[@]}" | sort -u); do
      # loading old params from YAML (dumped from LXD)
      test -r "${yml_oldconfig}" && {
        old_mac_address=$(get_value "config[volatile.${container_interface}.hwaddr]" "${yml_oldconfig}" none)
        old_ipv4_address=$(get_value "devices.${container_interface}[ipv4.address]" "${yml_oldconfig}" none)
        old_ipv6_address=$(get_value "devices.${container_interface}[ipv6.address]" "${yml_oldconfig}" none)
      }

      # detecting interface params from YAML
      parent_device=$(get_value "${main_network_section}.${container_interface}.parent" "${yml_localpath}" none)
      mac_address=$(get_value "${main_network_section}.${container_interface}.mac_address" "${yml_localpath}" "${old_mac_address}")
      ipv4_address=$(get_value "${main_network_section}.${container_interface}.ipv4_address" "${yml_localpath}" "${old_ipv4_address}")
      ipv6_address=$(get_value "${main_network_section}.${container_interface}.ipv6_address" "${yml_localpath}" "${old_ipv6_address}")
      iface_name=$(get_value "${main_network_section}.${container_interface}.host_name" "${yml_localpath}" "none")

      # checking profile for interface params overrides
      key_exists_in_yml "${yml_localpath}" "${profile_network_section}.${container_interface}" && {
        key_exists_in_yml "${yml_localpath}" "${profile_network_section}.${container_interface}.parent" && \
          parent_device=$(get_value "${profile_network_section}.${container_interface}.parent" "${yml_localpath}" none)
        key_exists_in_yml "${yml_localpath}" "${profile_network_section}.${container_interface}.parent" && \
          mac_address=$(get_value "${profile_network_section}.${container_interface}.mac_address" "${yml_localpath}" none)
        key_exists_in_yml "${yml_localpath}" "${profile_network_section}.${container_interface}.ipv4_address" && \
          ipv4_address=$(get_value "${profile_network_section}.${container_interface}.ipv4_address" "${yml_localpath}" none)
        key_exists_in_yml "${yml_localpath}" "${profile_network_section}.${container_interface}.ipv6_address" && \
          ipv6_address=$(get_value "${profile_network_section}.${container_interface}.ipv6_address" "${yml_localpath}" none)
        key_exists_in_yml "${yml_localpath}" "${profile_network_section}.${container_interface}.host_name" && \
          iface_name=$(get_value "${profile_network_section}.${container_interface}.host_name" "${yml_localpath}" none)
      }

      # checking and applying resulting params
      test "${parent_device}" == "none" && \
        show_fatal "No parent device detected for ${container_interface}, check network params in manifest."
      test "${ipv4_address}" == "none" -a "${ipv6_address}" == "none" && \
        show_notice "No IPv4/IPv6 addresses detected for ${container_interface}."

      show_notice "Adding ${parent_device} as ${container_interface} in ${container_name}"
      lxc network attach "${parent_device}" "${container_name}" "${container_interface}" || {
        show_fatal "Failed to attach ${parent_device} as ${container_interface} in ${container_name}"
      }

      test "${iface_name}" != "none" && {
        show_notice "Setting interface name to veth-${iface_name} for ${container_interface} from ${container_name}"
        lxc config device set "${container_name}" "${container_interface}" "host_name" "veth-${iface_name}" || \
          show_fatal "Failed to set interface name for ${container_name}"
      }
      test "${mac_address}" != "none" && {
        show_notice "Setting fixed MAC address to ${mac_address} for ${container_interface} from ${container_name}"
        lxc config set "${container_name}" "volatile.${container_interface}.hwaddr" "${mac_address}" || \
          show_fatal "Failed to set fixed MAC address for ${container_name}"
      }
      test "${ipv4_address}" != "none" && {
        show_notice "Setting fixed IPv4 address to ${ipv4_address} for ${container_interface} from ${container_name}"
        lxc config device set "${container_name}" "${container_interface}" "ipv4.address" "${ipv4_address}" || \
          show_fatal "Failed to set fixed IPv4 address for ${container_name}"
      }
      test "${ipv6_address}" != "none" && {
        show_notice "Setting fixed IPv6 address to ${ipv6_address} for ${container_interface} from ${container_name}"
        lxc config device set "${container_name}" "${container_interface}" "ipv6.address" "${ipv6_address}" || \
          show_fatal "Failed to set fixed IPv6 address for ${container_name}"
      }
    done
  }
  return "${err}"
}

function import_image() {
  local container_image="${1}"; local container_alias="${2}"; local -r image_hash=$(sha256sum "${container_image}" | cut -f 1 -d ' ')
  found_by_hash=$(lxc image list "${image_hash}" -c l --format csv | grep -cE "^${container_alias}$")
  found_by_alias=$(lxc image list "${container_alias}" -c l --format csv | grep -c "^${container_alias}$")
  test "${found_by_alias:-0}" -eq 1 -a "${found_by_hash:-0}" -eq 0 && {
    show_notice "Deleting existing image ${container_alias}"
    lxc image delete "${container_alias}" || show_fatal "Can't delete existing image"
  }
  test "${found_by_hash:-0}" -eq 1 && { show_notice "Found existing image with fingerprint ${image_hash}, skipping import"; return 0; }
  test "${found_by_hash:-0}" -eq 0 && {
    show_notice "Importing image ${container_image} as ${container_alias}"
    image_fingerprint=$(lxc image import "${container_image}" --alias="${container_alias}")
    show_notice "Imported as ${container_image} with fingerprint ${image_fingerprint##*: }"
  }
}

function export_image() {
  local image_alias="${1}";
  test -z "${image_alias}" && { show_error "Wrong usage! Usage: export-image image_name"; return 1; }
  test -d "${images_dir}" || mkdir -p "${images_dir}"
  image_exists "${image_alias}" && {
    show_notice "Exporting image ${image_alias} to ${images_dir}/${image_alias}.tar.gz"
    lxc image export "${image_alias}" "${images_dir}/${image_alias}" && \
    return 0;
  }
  show_error "Image ${image_alias} does not exist or something went wrong during export"
}

function set_container_parameter() {
  local container_name="${1}"; local parameter_name="${2}"; local parameter_value="${3}"
  lxc config set "${container_name}" "${parameter_name}" "${parameter_value}"
}

function set_container_autostart() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  container_boot_subkeys=$(get_keys "containers.${container_section}.boot" "${yml_localpath}")
  for container_boot_key in $container_boot_subkeys; do
      container_boot_value=$(get_value "containers.${container_section}.boot.${container_boot_key}" "${yml_localpath}")
      test "${container_boot_key}" = "autostart" && {
        show_notice "Setting boot.${container_boot_key} for ${container_name} to ${container_boot_value,,}"
        set_container_parameter "${container_name}" "boot.autostart" "${container_boot_value,,}"
      }
      test "${container_boot_key}" != "autostart" && {
        show_notice "Setting boot.autostart.${container_boot_key} for ${container_name} to ${container_boot_value,,}"
        set_container_parameter "${container_name}" "boot.autostart.${container_boot_key}" "${container_boot_value,,}"
      }
  done
}

function set_container_priveleges() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  container_priveleged_mode=$(get_value "containers.${container_section}.privileged" "${yml_localpath}" "false")
  container_nesting_mode=$(get_value "containers.${container_section}.nesting" "${yml_localpath}" "false")
  test "${container_priveleged_mode}" = "true" -o "${container_priveleged_mode}" = "True" -o "${container_priveleged_mode}" == "1" &&  {
    show_notice "Setting priveged mode for ${container_name} to ${container_priveleged_mode}"
    set_container_parameter "${container_name}" "security.privileged" "true"
  } || true
  test "${container_nesting_mode}" = "true" -o "${container_nesting_mode}" = "True" -o "${container_nesting_mode}" == "1" &&  {
    show_notice "Setting nesting mode for ${container_name} to ${container_nesting_mode}"
    set_container_parameter "${container_name}" "security.nesting" "true"
  } || true
}

function set_container_resource_limits() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"

  limits_set_main="containers.${container_section}.limits"
  declare -A container_limits
  for limit_entry in $(get_keys "${limits_set_main}" "${yml_localpath}"); do
    container_limits[${limit_entry}]=main
  done

  test "${selected_profile:-none}" != none && {
    key_exists_in_yml "${yml_localpath}" "containers.${container_section}.profiles.${selected_profile}.limits" && {
      limits_set_profile="containers.${container_section}.profiles.${selected_profile}.limits"
      for limit_entry in $(get_keys "${limits_set_profile}" "${yml_localpath}"); do
        container_limits[${limit_entry}]=profile
      done
    }
  }

  for limit_entry in "${!container_limits[@]}"; do
    limits_set="${limits_set_main}"
    test "${selected_profile:-none}" != none && {
      test "${container_limits[${limit_entry}]}" == profile && \
        limits_set="${limits_set_profile}"
    }
    container_rlimit_value=$(get_value "${limits_set}.${limit_entry/*/[${limit_entry}]}" "${yml_localpath}")
    show_notice "Setting limit limits.${limit_entry}=${container_rlimit_value} for ${container_name}"
    lxc config set "${container_name}" "limits.${limit_entry}" "${container_rlimit_value}"
  done
}

function set_device_resource_limits() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"; local target_device="${4}"
  device_limit_subkeys=$(get_keys "${devices_set}.${target_device}.limits" "${yml_localpath}")
  for device_limit_key in ${device_limit_subkeys}; do
    device_rlimit_value=$(get_value "${devices_set}.${target_device}.limits.${device_limit_key/*/[${device_limit_key}]}" "${yml_localpath}")
    show_notice "Setting limit ${device_limit_key}=${device_rlimit_value} for device \"${target_device}\""
    lxc config device set "${container_name}" "${target_device}" "${device_limit_key}" "${device_rlimit_value}"
  done
}

function set_container_environment() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  # small hack for PS1 in containers
  lxc config set "${container_name}" "environment.LC_HOST" "$(hostname -f)"
  container_env_subkeys=$(get_keys "containers.${container_section}.environment" "${yml_localpath}")
  for container_env_key in $container_env_subkeys; do
    container_env_value=$(get_value "containers.${container_section}.environment.${container_env_key}" "${yml_localpath}")
    show_notice "Setting environment variable ${container_env_key}=${container_env_value} for ${container_name}"
    lxc config set "${container_name}" "environment.${container_env_key}" "${container_env_value}"
  done
}

function set_container_user_params() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  container_description=$(get_value "containers.${container_section}.description" "${yml_localpath}")
  test -n "${container_description}" && lxc config set "${container_name}" "user.description" "${container_description}"
  container_role=$(get_value "containers.${container_section}.role" "${yml_localpath}")
  test -n "${container_role}" && lxc config set "${container_name}" "user.role" "${container_role}"
  container_protection=$(get_value "containers.${container_section}.protected" "${yml_localpath}")
  test -n "${container_protection}" && lxc config set "${container_name}" "user.protected" "${container_protection,,}"
  lxc config set "${container_name}" "user.deployed_at" "$(date '+%F-%T-%Z')"
  lxc config set "${container_name}" "user.deployed_from" "${image_alias}"
  lxc config set "${container_name}" "user.deployed_with" "${yml_localpath}"
  lxc config set "${container_name}" "user.deployed_by" "${LOGNAME:-${USER}}"
}

function set_container_cloudconfig_params() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  container_cloud_config=$(get_value "containers.${container_section}.cloud-config" "${yml_localpath}")
  test -n "${container_description}" && {
    show_notice "Importing cloud-config params to container config"
    echo -e "#cloud-config\n${container_cloud_config}" | sed "s/FQDN/${our_hostname:-none}/"| lxc config set "${container_name}" "user.user-data" -
  }
}

function set_container_idmap_param() {
  local container_name="${1}"; local container_section="${2}"; local yml_localpath="${3}"
  container_idmap=$(get_value "containers.${container_section}.[raw.idmap]" "${yml_localpath}" "null")
  test "${container_idmap}" != null && {
    show_notice "Setting idmap param for container"
    set_container_parameter "${container_name}" raw.idmap "${container_idmap}"
  }
}

function proceed_section() {
  local container_section="${1}"; local yml_localpath="${2}"; local containers_basedir="${3}"
  container_name=$(get_value "containers.${container_section}.name" "${yml_localpath}" "${container_section}")
  container_name_profile=$(get_value "containers.${container_section}.profiles.${selected_profile:-none}.name" "${yml_localpath}" none)
  test "${container_name_profile}" != none && container_name=${container_name_profile}
  container_datadir="${containers_basedir}/${container_name}"
  yml_contains_limits_for_container "${container_name}" "${container_section}" "${yml_localpath}"
  test -d "${container_datadir}" || { show_notice "Creating directory ${container_datadir}"; mkdir -p "${container_datadir}"; }
  yml_oldconfig="${container_datadir}/${container_name}.lxd"
  container_exists "${container_name}" && {
    show_notice "Saving current configuration of ${container_name} as ${yml_oldconfig}"
    lxc config show "${container_name}" > "${yml_oldconfig}"
  }

  container_tests=$(get_value "containers.${container_section}.tests" "${yml_localpath}")
  test "${container_tests:0:7}" == "http://" -o "${container_tests:0:8}" == "https://" && {
    tests_filename=$( basename "${container_tests}" )
    tests_version=$( sed -rn 's|\w+-(.+)\.py|\1|p' <<< "${tests_filename}" )
    container_local_tests="${containers_cachedir}/tests/${container_name}/${tests_version}/${container_name}.py"
    download_file "${container_tests}" "${container_local_tests}" || show_fatal "Failed to download ${container_tests}"
  }

  container_postdeploy_tests=$(get_value "containers.${container_section}.postdeploy-tests" "${yml_localpath}")
  test "${container_postdeploy_tests:0:7}" == "http://" -o "${container_postdeploy_tests:0:8}" == "https://" && {
    postdeploy_tests_filename=$( basename "${container_postdeploy_tests}" )
    postdeploy_tests_version=$( sed -rn 's|\w+-(.+)\.py|\1|p' <<< "${postdeploy_tests_filename}" )
    container_local_postdeploy_tests="${containers_cachedir}/tests/${container_name}/${tests_version}/${container_name}-postdeploy.py"
    download_file "${container_postdeploy_tests}" "${container_local_postdeploy_tests}" || show_fatal "Failed to download ${container_postdeploy_tests}"
  }

  container_image=$(get_value "containers.${container_section}.image" "${yml_localpath}")
  image_filename=${container_image##*/}
  image_alias=${image_filename%%.tar.*}
  test "${container_image:0:7}" == "http://" -o "${container_image:0:8}" == "https://" && {
    container_local_image="${containers_cachedir}/${image_filename}"
    download_file "${container_image}" "${container_local_image}" || show_fatal "Failed to download ${container_image}"
    import_image "${container_local_image}" "${image_alias}" || show_fatal "Failed to import ${container_local_image} as ${image_alias}"
  }
  create_container "${container_name}" "${image_alias}" || show_fatal "Failed to create container ${container_name} from ${image_alias} image"
  set_container_user_params "${container_name}" "${container_section}" "${yml_localpath}"
  mount_directories_to_container "${container_name}" "${container_section}" "${yml_localpath}" || show_fatal "Failed to mount directories to container ${container_name}"
  set_network_parameters_for_container "${container_name}" "${container_section}" "${yml_localpath}" || show_fatal "Failed to setup network parameters for container ${container_name}"
  set_container_autostart "${container_name}" "${container_section}" "${yml_localpath}"
  set_container_resource_limits "${container_name}" "${container_section}" "${yml_localpath}"
  set_container_priveleges "${container_name}" "${container_section}" "${yml_localpath}"
  set_container_environment "${container_name}" "${container_section}" "${yml_localpath}"
  set_container_idmap_param "${container_name}" "${container_section}" "${yml_localpath}"
  set_container_cloudconfig_params  "${container_name}" "${container_section}" "${yml_localpath}"
}

function check_container() {
  local container_section="${1}"; local yml_localpath="${2}"
  local container_name; local container_tests; local container_postdeploy_tests; local err=0;
  container_name=$(get_value "containers.${container_section}.name" "${yml_localpath}" "${container_section}")
  container_name_profile=$(get_value "containers.${container_section}.profiles.${selected_profile:-none}.name" "${yml_localpath}" none)
  test "${container_name_profile}" != none && container_name=${container_name_profile}
  container_tests=$(get_value "containers.${container_section}.tests" "${yml_localpath}" none)
  container_postdeploy_tests=$(get_value "containers.${container_section}.postdeploy-tests" "${yml_localpath}" none)

  # returning if no tests key found in yml
  test "${container_tests}" == none && { show_warning "There are no main tests in lxhelper.yml, you shoud add it."; return 0; }
  test "${container_postdeploy_tests}" == none && show_warning "There are no postdeploy tests in lxhelper.yml, you shoud add it."

  # detecting tests file
  test -r "${containers_cachedir}/${container_tests}" && container_local_tests="${container_tests}" || {
    test "${container_tests:0:7}" == "http://" -o "${container_tests:0:8}" == "https://" && {
      tests_filename=$( basename "${container_tests}" )
      tests_version=$( sed -rn 's|\w+-(.+)\.py|\1|p' <<< "${tests_filename}" )
      container_local_tests="${containers_cachedir}/tests/${container_name}/${tests_version}/${container_name}.py"
    }
  }
  test -r "${container_local_tests}" || {
    err=1
    show_error "Can't find tests at ${container_local_tests}."
  }

  test -r "${containers_cachedir}/${container_postdeploy_tests}" && container_local_postdeploy_tests="${container_postdeploy_tests}" || {
    test "${container_postdeploy_tests:0:7}" == "http://" -o "${container_tests:0:8}" == "https://" && {
      postdeploy_tests_filename=$( basename "${container_postdeploy_tests}" )
      postdeploy_tests_version=$( sed -rn 's|\w+-(.+)\-postdeploy\.py|\1|p' <<< "${postdeploy_tests_filename}" )
      container_local_postdeploy_tests="${containers_cachedir}/tests/${container_name}/${postdeploy_tests_version}/${container_name}-postdeploy.py"
    }
  }
  test -r "${container_local_postdeploy_tests}" || show_warning "Can't find postdeploy tests at ${container_local_postdeploy_tests}."

  # testing if needed python modules are installed
  test "${err}" == 0 && {
    have_testinfra && have_pylxd || {
      show_error "Can't run downloaded tests. Check if testinfra and pylxd python modules are installed correctly."
      err=1
    }
  }

  # running tests
  test "${err}" == 0 && {
    wait_for_container_to_boot "${container_name}"
    testinfra_custom_delay
    show_notice "Checking container ${container_name} with main tests"
    $pytest_script -sxq --hosts="lxc://${container_name}" "${container_local_tests}" || err=1
    test "${container_postdeploy_tests}" != none && {
      show_notice "Checking container ${container_name} with postdeploy tests"
      $pytest_script -sxq --hosts="lxc://${container_name}" "${container_local_postdeploy_tests}" || err=1
    }
  }
  return "${err}"
}

function download_image() {
  local container_name="${1}";
  test -z "${container_name}" && show_fatal "Wrong usage! Usage: download_image container_name"
  load_params_from_yml "${container_name}"
  echo "${containers_sections}" | grep -q "${container_name}" || show_fatal "No container ${container_name} in ${yml_localpath}!"
  download_image_for_container "${container_name}" "${yml_localpath}" "${containers_basedir}"
}

function download_image_for_container() {
  local container_section="${1}"; local yml_localpath="${2}"; local containers_basedir="${3}"
  container_name=$(get_value "containers.${container_section}.name" "${yml_localpath}" "${container_section}")
  container_name_profile=$(get_value "containers.${container_section}.profiles.${selected_profile:-none}.name" "${yml_localpath}" none)
  test "${container_name_profile}" != none && container_name=${container_name_profile}
  container_datadir="${containers_basedir}/${container_name}"
  test -d "${container_datadir}" || { show_notice "Creating directory ${container_datadir}"; mkdir -p "${container_datadir}"; }
  yml_oldconfig="${container_datadir}/${container_name}.lxd"
  container_exists "${container_name}" && {
    show_notice "Saving current configuration of ${container_name} as ${yml_oldconfig}"
    lxc config show "${container_name}" > "${yml_oldconfig}"
  }

  container_tests=$(get_value "containers.${container_section}.tests" "${yml_localpath}")
  test "${container_tests:0:7}" == "http://" -o "${container_tests:0:8}" == "https://" && {
    tests_filename=$( basename "${container_tests}" )
    tests_version=$( sed -rn 's|\w+-(.+)\.py|\1|p' <<< "${tests_filename}" )
    container_local_tests="${containers_cachedir}/tests/${container_name}/${tests_version}/${container_name}.py"
    download_file "${container_tests}" "${container_local_tests}" || show_fatal "Failed to download ${container_tests}"
  }

  container_image=$(get_value "containers.${container_section}.image" "${yml_localpath}")
  image_filename=${container_image##*/}
  test "${container_image:0:7}" == "http://" -o "${container_image:0:8}" == "https://" && {
    container_local_image="${containers_cachedir}/${image_filename}"
    download_file "${container_image}" "${container_local_image}" || show_fatal "Failed to download ${container_image}"
  }
}

function get_yml() {
  local yml_origin="${1}"; local yml_filename="${yml_origin##*/}"
  test "${yml_origin:0:7}" == "http://" -o "${yml_origin:0:8}" == "https://" && {
    yml_localpath="${yml_dir}/${yml_filename}"
    show_notice "Trying to download remote manifest as ${yml_localpath}"
    download_file "${yml_origin}" "${yml_localpath}" "${download_transport:-http}" || show_fatal "Failed to download ${yml_origin}"
  } || yml_localpath="${yml_origin}"
  test -f "${yml_localpath}" || show_fatal "yml config ${yml_localpath} not found."
}

function load_params_from_yml() {
  local container_name="${1}"
  get_yml "${yml_path:-$yml_dir/$container_name.yml}"
  yml_is_valid "${yml_localpath}"
  check_and_update_yml_version
  show_notice "Reading basedir and cachedir from ${yml_localpath}"
  containers_basedir=$(get_value basedir "${yml_localpath}" "${containers_data_dir}")
  test -d "${containers_basedir}" || { show_notice "Creating directory ${containers_basedir}"; mkdir -p "${containers_basedir}"; }
  containers_cachedir=$(get_value cachedir "${yml_localpath}" "${images_dir}")
  test -d "${containers_cachedir}" || { show_notice "Creating directory ${containers_cachedir}"; mkdir -p "${containers_cachedir}"; }
  containers_sections=$(get_keys containers "${yml_localpath}")
}

function create_image() {
  local container_name="${1}"; local image_alias="${2:-$container_name}"; local container_was_running=0
  [[ ${container_name} == *"-tpl" ]] || { show_error "Container ${container_name} has no -tpl prefix. Skipping."; return 1; }
  container_exists "${container_name}" || { show_error "Container ${container_name} doesn't exist. Skipping."; return 1; }
  show_notice "Creating image ${image_alias} from container ${container_name}"
  clean_container "${container_name}"
  container_is_running "${container_name}" && {
    show_notice "Stopping container ${container_name}"
    container_was_running=1
    lxc stop "${container_name}"
  }
  image_exists "${image_alias}" && {
    show_notice "Deleting the existing image ${image_alias}"
    lxc image delete "${image_alias}"
  }
  show_notice "Creating image $image_alias from ${container_name} container"
  lxc publish "${container_name}" --alias="${image_alias}"
  test "${container_was_running}" -eq "1" && lxc start "${container_name}"
}

function deploy_containers() {
  test -z "${yml_path}" && { show_error "Set path to a YML-config!"; return 1; }
  load_params_from_yml
  for container_section in ${containers_sections}; do
    proceed_section "${container_section}" "${yml_localpath}" "${containers_basedir}"
    push_profile "${container_section}"
  done
}

function push_profile() {
  local container_name="${1}"; local default_profile; local custom_profile
  default_profile="$(mktemp)"; custom_profile="$(mktemp)"
  show_notice "Pushing profiles to container \"${container_name}\"..."
  test -z "${yml_localpath}" && "${yq_cmd}" r "${yml_dir}/${container_name}.yml" "containers.${container_name}.profiles.default" 2>/dev/null > "${default_profile}"
  test -z "${yml_localpath}" || "${yq_cmd}" r "${yml_localpath}" "containers.${container_name}.profiles.default" 2>/dev/null > "${default_profile}"
  test -s "${default_profile}" && "${yq_cmd}" w -i "${default_profile}" profile.name default && \
    lxc file push "${default_profile}" "${container_name}${profiles_dir}/default.yml" -p && \
      show_notice "Default profile found and pushed"
  test -n "${selected_profile:-}" && {
    test -z "${yml_localpath}" && "${yq_cmd}" r "${yml_dir}/${container_name}.yml" "containers.${container_name}.profiles.${selected_profile}" 2>/dev/null > "${custom_profile}"
    test -z "${yml_localpath}" || "${yq_cmd}" r "${yml_localpath}" "containers.${container_name}.profiles.${selected_profile}" 2>/dev/null > "${custom_profile}"
    test -s "${custom_profile}" && "${yq_cmd}" w -i "${custom_profile}" profile.name "${selected_profile}" && \
      lxc file push "${custom_profile}" "${container_name}${profiles_dir}/custom.yml" -p && \
        show_notice "Profile \"${selected_profile}\" found and pushed"
  }
  test -f "${default_profile}" && rm "${default_profile}"
  test -f "${custom_profile}" && rm "${custom_profile}"
}

function push_files() {
  local container_name="${1}"; local source_path; local target_path
  local uid; local gid; local recursive
  key_exists_in_yml "${yml_localpath}" "containers.${container_name}.push" && {
    show_notice "Pushing files to container \"${container_name}\"..."
    source_path=$(get_value "containers.${container_name}.push.source" "${yml_localpath}" none)
    target_path=$(get_value "containers.${container_name}.push.target" "${yml_localpath}" none)
    uid=$(get_value "containers.${container_name}.push.uid" "${yml_localpath}" 0)
    gid=$(get_value "containers.${container_name}.push.gid" "${yml_localpath}" 0)
    recursive=$(get_value "containers.${container_name}.push.recursive" "${yml_localpath}" false)

    test "${source_path}" != none -a "${target_path}" != none && {
      test "${recursive}" != true && \
        lxc file push -p --uid "${uid}" --gid "${gid}" "${source_path}" "${container_name}${target_path}"
      test "${recursive}" == true && \
        lxc file push -p --recursive "${source_path}" "${container_name}${target_path}"
    }
  }
}

function deploy_container() {
  local container_name="${1}";
  test -z "${container_name}" && show_fatal "Wrong usage! Usage: deploy_container container_name"
  load_params_from_yml "${container_name}"
  echo "${containers_sections}" | grep -q "${container_name}" || show_fatal "No container ${container_name} in ${yml_localpath}!"
  proceed_section "${container_name}" "${yml_localpath}" "${containers_basedir}"
  push_profile "${container_name}"
  push_files "${container_name}"
  test "${skip_start:-false}" = "false" && {
    show_notice "Starting container ${container_name}"
    lxc start "${container_name}"
    push_sshkey "${container_name}"
    check_container "${container_name}" "${yml_localpath}"
  }
}


function update_config() {
  local err=0; local yml_config=$1;
  grep -q '#cloud-config' "${yml_config}" && {
    sed -r 's/cloud-config:\s\|/cloud-config:/g;/#cloud-config/d' -i "${yml_config}" || err=1
  }
  "${yq_cmd}" w -i "${yml_config}" version "${yml_current_ver}" || err=1
  test "${err}" == "0" && show_notice "Successfully updated the YML-config: ${yml_config}"
  test "${err}" == "1" && show_error "Something went wrong while updating version of ${yml_config}"
  return "${err}"
}

function update_configs() {
  local path=${1}; local yml_config_list=($(ls -d "${path:-/usr/local/etc/lxc}"/*.yml))
  for yml_config in "${yml_config_list[@]}"; do
    update_config "${yml_config}"
  done
}

function check_and_update_yml_version() {
  yml_version=$(get_value "version" "${yml_localpath}" "0")
  grep -qE "(p\.)?osshelp\.ru" "${yml_localpath}" && {
    show_warning "\"osshelp.ru\" is deprecated. Use \"oss.help\" instead!"
  }
  test "${yml_version}" -eq "${yml_current_ver}" && return
  test "${yml_version}" -le "${yml_deprecated_ver}" -o "${yml_version}" -eq "0" && {
    show_notice "YML-config version is missing or deprecated, updating it."
    update_config "${yml_localpath}"
  }
  test "${yml_version}" -gt "${yml_current_ver}" && show_fatal "Inappropriate YML-config version! Seems that you need to update lxhelper and lxd-functions!"
}

function update_image() {
  local image_name="${1}"
  test -z "${image_name}" && show_fatal "Wrong usage! Usage: lxhelper update-image image_name"
  image_exists "${image_name}" || show_fatal "Image ${image_name} does not exist, nothing to update"
  container_exists "${image_name}" || show_fatal "Container ${image_name} does not exist, can't update it's image"
  create_image "${image_name}" && export_image "${image_name}"
}

function check_and_make_sshkey() {
  test ! -r /root/.ssh/id_rsa && {
    ssh-keygen -t rsa -f /root/.ssh/id_rsa -N ""
  } && return
  test ! -r /root/.ssh/id_rsa.pub && {
    ssh-keygen -y -f /root/.ssh/id_rsa > /root/.ssh/id_rsa.pub && chmod 600 .ssh/id_rsa.pub
  }
}
function push_sshkey() {
  container_name="${1}"

  test "$(get_value "containers.${container_name}.sshkey_push_disable" "${yml_localpath}" false)" == 'true' || {
    check_and_make_sshkey
    lxc file push /root/.ssh/id_rsa.pub "${container_name}"/root/.ssh/authorized_keys.temp
    {
      echo "test -s /root/.ssh/authorized_keys ||"
      echo "mv /root/.ssh/authorized_keys.temp /root/.ssh/authorized_keys"
    } | lxc exec "${container_name}" -- bash -s
    {
      echo "test -s /root/.ssh/authorized_keys &&"
      echo "cat /root/.ssh/authorized_keys >> /root/.ssh/authorized_keys.temp;"
      echo "mv /root/.ssh/authorized_keys.temp /root/.ssh/authorized_keys"
    } | lxc exec "${container_name}" -- bash -s
  }
}


test -x "${lxc_cmd}" || { show_error "Can't find lxc (lxd client), you should install it first: apt-get install lxd-client"; exit 1; }
test -x "${yq_cmd}" || { show_error "Can't find yq (YAML processor), you should install it first"; exit 1; }