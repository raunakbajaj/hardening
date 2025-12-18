#!/bin/bash

# shellcheck disable=1090
# shellcheck disable=2009
# shellcheck disable=2034

set -u -o pipefail

# Bash detection disabled for EC2 Image Builder compatibility
# The script is explicitly called with bash from ubuntu.sh

if ! [ -x "$(command -v systemctl)" ]; then
  echo "systemctl required. Exiting."
  exit 1
fi

function main {
  clear

  # Get the directory where this script is located
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  
  # Change to script directory to ensure relative paths work
  cd "$SCRIPT_DIR"

  REQUIREDPROGS='arp dig ping w'
  REQFAILED=0
  for p in $REQUIREDPROGS; do
    if ! command -v "$p" >/dev/null 2>&1; then
      echo "$p is required."
      REQFAILED=1
    fi
  done

  if [ $REQFAILED = 1 ]; then
    apt-get -qq update
    apt-get -qq install bind9-dnsutils iputils-ping net-tools procps --no-install-recommends
  fi

  ARPBIN="$(command -v arp)"
  DIGBIN="$(command -v dig)"
  PINGBIN="$(command -v ping)"
  WBIN="$(command -v w)"
  WHOBIN="$(command -v who)"
  LXC="0"

  if resolvectl status >/dev/null 2>&1; then
    SERVERIP="$(ip route get "$(resolvectl status |\
      grep -E 'DNS (Server:|Servers:)' | tail -n1 |\
      awk '{print $NF}')" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' |\
      tail -n1)"
  else
    SERVERIP="$(ip route get "$(grep '^nameserver' /etc/resolv.conf |\
      tail -n1 | awk '{print $NF}')" |\
      grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -n1)"
  fi

  if grep -qE 'container=lxc|container=lxd' /proc/1/environ; then
    LXC="1"
  fi

  if grep -s "AUTOFILL='Y'" ./ubuntu.cfg; then
    USERIP="$($WHOBIN | awk '{print $NF}' | tr -d '()' |\
      grep -E '^[0-9]' | head -n1)"

    if [[ "$USERIP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      ADMINIP="$USERIP"
    else
      ADMINIP="$(hostname -I | sed -E 's/\.[0-9]+ /.0\/24 /g')"
    fi

    sed -i "s/FW_ADMIN='/FW_ADMIN='$ADMINIP /" ./ubuntu.cfg
    sed -i "s/SSH_GRPS='/SSH_GRPS='$(id "$($WBIN -ih | awk '{print $1}' | head -n1)" -ng) /" ./ubuntu.cfg
    sed -i "s/CHANGEME=''/CHANGEME='$(date +%s)'/" ./ubuntu.cfg
    sed -i "s/VERBOSE='N'/VERBOSE='Y'/" ./ubuntu.cfg
  fi

  source ./ubuntu.cfg

  readonly ADDUSER
  readonly ADMINEMAIL
  readonly ARPBIN
  readonly AUDITDCONF
  readonly AUDITD_MODE
  readonly AUDITD_RULES
  readonly AUDITRULES
  readonly AUTOFILL
  readonly CHANGEME
  readonly COMMONACCOUNT
  readonly COMMONAUTH
  readonly COMMONPASSWD
  readonly COREDUMPCONF
  readonly DEFAULTGRUB
  readonly DISABLEFS
  readonly DISABLEMOD
  readonly DISABLENET
  readonly FAILLOCKCONF
  readonly FW_ADMIN
  readonly JOURNALDCONF
  readonly KEEP_SNAPD
  readonly LIMITSCONF
  readonly LOGINDCONF
  readonly LOGINDEFS
  readonly LOGROTATE
  readonly LOGROTATE_CONF
  readonly LXC
  readonly NTPSERVERPOOL
  readonly PAMLOGIN
  readonly PSADCONF
  readonly PSADDL
  readonly RESOLVEDCONF
  readonly RKHUNTERCONF
  readonly RSYSLOGCONF
  readonly SECURITYACCESS
  readonly SERVERIP
  readonly SSHDFILE
  readonly SSHFILE
  readonly SSH_GRPS
  readonly SSH_PORT
  readonly SYSCTL
  readonly SYSCTL_CONF
  readonly SYSTEMCONF
  readonly TIMEDATECTL
  readonly TIMESYNCD
  readonly UFWDEFAULT
  readonly USERADD
  readonly USERCONF
  readonly VERBOSE
  readonly WBIN

  for s in ./scripts/*; do
    [[ -f $s ]] || break

    source "$s"
  done

  # Confirmed start 
  f_pre
  f_journalctl
  f_timesyncd
  f_resolvedconf
  f_adduser
  f_rootaccess
  f_coredump
  f_aptget
  f_postfix
  f_apport
  f_motdnews
  f_hosts
  f_issue
  f_sudo
  f_logindefs
  f_prelink
  f_firewall
  f_sshconfig
  f_sshdconfig
  f_cron
  f_rhosts
  f_umask
  f_path
  f_aptget_clean
  f_systemddelta
  f_post
  f_checkreboot
  # Confirmed end

  # Doubt start 
  f_password
  f_kernel
  f_logindconf  
  f_suid
  f_fstab
  
  # Doubt end  

  #Issue start
  #f_aptget_configure
  #Issue end

  
  # f_disablenet  # COMMENTED: May disable network protocols GUI needs
  # f_disablefs  # COMMENTED: May disable filesystems GUI needs
  # f_disablemod  # COMMENTED: Disables USB, Bluetooth, sound - breaks GUI
  # f_systemdconf  # COMMENTED: Process limits too restrictive for GUI 
  # f_sysctl  # COMMENTED: Network restrictions may break GUI networking
  # f_limitsconf  # COMMENTED: Process limits too restrictive for GUI
  # f_package_install  # COMMENTED: May install conflicting packages
  # f_psad  # COMMENTED: Aggressive intrusion detection may block GUI
  # f_usbguard  # COMMENTED: Blocks USB devices - breaks GUI peripherals
  # f_rkhunter  # COMMENTED: May interfere with GUI file operations
  # f_ctrlaltdel  # COMMENTED: Disables Ctrl+Alt+Del - may confuse GUI users
  # f_auditd  # COMMENTED: Aggressive auditing may slow down GUI
  # f_aide  # COMMENTED: File integrity checking may interfere with GUI
  # f_users  # COMMENTED: Removes system users that GUI might need
  # f_lockroot  # COMMENTED: Locks root account - may break GUI admin tasks
  # f_package_remove  # COMMENTED: Removes packages that GUI might depend on
  # f_restrictcompilers  # COMMENTED: May break development tools in GUI
  # f_aa_enforce  # COMMENTED: AppArmor enforcement may break GUI applications
  # f_aide_post  # COMMENTED: File integrity checking may interfere with GUI
  # f_aide_timer  # COMMENTED: File integrity checking may interfere with GUI
  # f_aptget_noexec  # COMMENTED: /tmp remount operations fail in EC2 environment
  

  echo
}

LOGFILE="hardening-$(hostname --short)-$(date +%y%m%d).log"
echo "[HARDENING LOG - $(hostname --fqdn) - $(LANG=C date)]" >> "$LOGFILE"

main "$@" | tee -a "$LOGFILE"