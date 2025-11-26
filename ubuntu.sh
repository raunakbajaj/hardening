#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[+] Running GUI-safe CIS hardening"

#
# 1. Basic package updates (safe)
#
echo "[+] Updating APT package lists"
apt-get update -y
