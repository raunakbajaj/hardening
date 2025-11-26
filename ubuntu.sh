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
# 10. Logrotate hardening (safe)
#
echo "[+] Securing logrotate config"
sed -i 's/^create.*/create 0640 root adm/' /etc/logrotate.conf


echo "[+] GUI-safe CIS hardening completed successfully"
exit 0
