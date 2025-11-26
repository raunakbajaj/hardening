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
