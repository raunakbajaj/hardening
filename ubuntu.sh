#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[+] Running GUI-safe CIS hardening"

#
# 1. Basic package updates (safe)
#
echo "[+] Updating APT package lists"
apt-get update -y


#
# 2. Enable unattended upgrades (safe)
#
echo "[+] Enabling unattended-upgrades"
apt-get install -y unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

#
# 3. Configure login.defs (safe)
#
echo "[+] Applying safe login.defs hardening"
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

#
# 4. Configure password aging for existing users (safe)
#
echo "[+] Updating password aging for existing users"
for u in $(awk -F: '($3 >= 1000 && $3 < 65534) {print $1}' /etc/passwd); do
    chage --maxdays 90 --mindays 1 --warndays 14 "$u" || true
done

#
# 5. Filesystem permission hardening (safe)
#
echo "[+] Securing /etc permissions"
chmod 0755 /etc
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod 0640 /etc/shadow
chmod 0640 /etc/gshadow

#
# 6. Disable core dumps (safe)
#
echo "[+] Disabling core dumps"
echo '* hard core 0' > /etc/security/limits.d/99-hardening.conf

#
# 7. Configure sysctl network hardening (safe subset)
#
echo "[+] Applying sysctl safe network settings"
cat <<EOF >/etc/sysctl.d/99-safe-hardening.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.kptr_restrict = 1
EOF
sysctl --system || true

#
# 8. SSH hardening (safe subset)
#
echo "[+] Applying SSH hardening"
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config


#
# 9. Remove world-writable permissions (safe)
#
echo "[+] Removing world-writable permissions"
find / -xdev -type f -perm -0002 -exec chmod o-w {} + || true
find / -xdev -type d -perm -0002 -exec chmod o-t {} + || true

#
# 10. Logrotate hardening (safe)
#
echo "[+] Securing logrotate config"
sed -i 's/^create.*/create 0640 root adm/' /etc/logrotate.conf

#
# 11. Enable firewall (ufw, safe)
#
echo "[+] Enabling UFW firewall"
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw --force enable


#Custom script 

#Disable root login via ssh
sudo sed -i '/^#\?PermitRootLogin/s/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config
#sudo systemctl restart sshd

#libpam-tmpdir is a PAM module that automatically creates a private temporary directory (/tmp and /var/tmp) for each user session to avoid common dir
sudo apt install libpam-tmpdir -y


#apt-listchanges — Show changelogs and security updates before upgrading
sudo apt install apt-listchanges -y

#needrestart — Detects daemons needing restart after updates

#fail2ban — Protects SSH and other services from brute-force attacks
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo chmod 600 /etc/fail2ban/jail.local
#sudo systemctl restart fail2ban


#nstalls Linux Auditing System components that are used to track and log security-relevant events — such as file access, privilege use, system calls, and policy violations
sudo apt install auditd audispd-plugins
sudo systemctl enable --now auditd

#Disable unused protocols
sudo tee /etc/modprobe.d/disable-unused-protocols.conf > /dev/null <<EOF
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
sudo update-initramfs -u

# Disable hard drive
sudo tee /etc/modprobe.d/blacklist-usb-storage.conf > /dev/null <<EOF
# Disable USB storage devices
install usb-storage /bin/false
EOF

sudo update-initramfs -u



#Unauth banner
sudo tee /etc/issue > /dev/null <<EOF
****************************************************************
* WARNING: Unauthorized access to this system is prohibited  *
* All activities are monitored and logged.                    *
* Disconnect immediately if you are not an authorized user.   *
****************************************************************
EOF


sudo tee /etc/issue.net > /dev/null <<EOF
****************************************************************
* WARNING: Unauthorized access to this system is prohibited   *
* All activities are monitored and logged.                    *
* Disconnect immediately if you are not an authorized user.   *
****************************************************************
EOF

sudo sed -i '/^#\?Banner/ c\Banner /etc/issue.net' /etc/ssh/sshd_config 



sudo tee /etc/sysctl.d/99-cis.conf > /dev/null <<EOF
# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Example: Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

sudo sysctl --system



sudo dpkg --configure -a
sudo apt install -f -y


set -u -o pipefail

if ! ps -p $$ | grep -si bash; then
  echo "Sorry, this script requires bash."
  exit 1
fi

if ! [ -x "$(command -v systemctl)" ]; then
  echo "systemctl required. Exiting."
  exit 1
fi

function main {
  clear

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

  f_pre

  

  echo
}

LOGFILE="hardening-$(hostname --short)-$(date +%y%m%d).log"
echo "[HARDENING LOG - $(hostname --fqdn) - $(LANG=C date)]" >> "$LOGFILE"

main "$@" | tee -a "$LOGFILE"

echo "[+] GUI-safe CIS hardening completed successfully"
exit 0
