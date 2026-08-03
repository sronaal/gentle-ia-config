---
name: anonymity-macchanger
description: MAC address and hostname randomization for operational security
version: 1.0.0
phase: post
category: opsec
tags: [anonymity, mac, opsec, randomization]
tools: [macchanger, network-manager, ip]
difficulty: basic
opsec_level: silent
time_estimate: 30s
severity_if_found: N/A
related_skills:
  - anonymity-dns-leak
  - anonymity-traffic-blending
mitre_attack:
  - T1562
  - T1562.006
  - T1595
---

## When to Use

Use this skill at the START of any engagement to anonymize the attack machine's
network identity. MAC addresses are logged by switches, DHCP servers, and
wireless access points — they can tie your traffic to a physical device.
Combine with hostname and machine-id randomization to prevent passive
fingerprinting across networks.

## Prerequisites

- Root access on the local machine (required for MAC changes)
- `macchanger` installed (`apt install macchanger`)
- Network interfaces identified (`ip link show`)
- Physical network access that tolerates interface restart (disconnects briefly)
- Systemd-based Linux for hostname randomization

## Procedure

```bash
# ═══════════════════════════════════════════════════════════
# 1. LIST INTERFACES AND CURRENT MAC ADDRESSES
# ═══════════════════════════════════════════════════════════
ip link show
# Identify the target interface (e.g., eth0, wlan0, ens33)
# Note the current MAC (listed as "link/ether aa:bb:cc:dd:ee:ff")

# View MAC vendor:
macchanger -s eth0

# ═══════════════════════════════════════════════════════════
# 2. MAC RANDOMIZATION — Per interface
# ═══════════════════════════════════════════════════════════
# Bring interface down first
sudo ip link set eth0 down

# Random MAC address (completely random, vendor bytes included)
sudo macchanger -r eth0

# Random MAC with OUI preserved (appears as real vendor)
sudo macchanger -e eth0

# Specific vendor MAC (e.g., Intel, Realtek, Cisco)
sudo macchanger -m 00:14:22:XX:XX:XX eth0

# Specific MAC address (you choose)
sudo macchanger -m 00:11:22:33:44:55 eth0

# Bring interface back up
sudo ip link set eth0 up

# Verify the new MAC
macchanger -s eth0
ip link show eth0

# ═══════════════════════════════════════════════════════════
# 3. VENDOR-SPECIFIC MAC GENERATION
# ═══════════════════════════════════════════════════════════
# Common OUI prefixes for blending:
# Intel:    00:1B:21, 3C:97:0E, A0:88:B4
# Realtek:  00:E0:4C, 00:E0:18, 00:50:8D
# Broadcom: 00:10:18, 00:90:4C, A4:1F:72
# Cisco:    00:14:5C, 00:1A:A1, FC:99:47
# Samsung:  00:15:99, 00:23:D4, E0:DB:55
# Apple:    00:1E:C2, A8:66:7F, F0:18:98

# Set a MAC resembling an Intel NIC:
sudo macchanger -m 00:1B:21:$(openssl rand -hex 3 | sed 's/\(..\)/\1:/g; s/:$//') eth0

# Set a MAC resembling a Samsung device:
sudo macchanger -m 00:15:99:$(openssl rand -hex 3 | sed 's/\(..\)/\1:/g; s/:$//') eth0

# ═══════════════════════════════════════════════════════════
# 4. PERSISTENT MAC CHANGE — Survives reboot
# ═══════════════════════════════════════════════════════════
# ── NetworkManager ─────────────────────────────────────────
# Edit the connection profile
nmcli connection show
nmcli connection modify "Wired connection 1" 802-3-ethernet.cloned-mac-address random

# Make it permanent (always randomize at boot):
nmcli connection modify "Wired connection 1" 802-3-ethernet.cloned-mac-address stable
# Or random:
nmcli connection modify "Wired connection 1" 802-3-ethernet.cloned-mac-address random

# ── systemd-networkd ──────────────────────────────────────
cat >> /etc/systemd/network/20-wired.network << 'NETCONF'
[Match]
Name=eth0

[Link]
MACAddressPolicy=random
NETCONF

# ── udev rule (MAC spoofing at every boot) ────────────────
cat > /etc/udev/rules.d/81-mac-spoof.rules << 'UDEV'
ACTION=="add", SUBSYSTEM=="net", ATTR{address}=="", KERNEL=="eth*", RUN+="/usr/bin/macchanger -r $name"
UDEV

# ═══════════════════════════════════════════════════════════
# 5. HOSTNAME RANDOMIZATION
# ═══════════════════════════════════════════════════════════
# Generate a plausible-looking hostname
# Option A: Random Ubuntu-style hostname
NEW_HOSTNAME=$(shuf -n1 <<< "ubuntu-desktop-$(shuf -i 1000-9999 -n1)")

# Option B: Random Windows-style hostname
NEW_HOSTNAME="DESKTOP-$(openssl rand -hex 4 | tr 'a-f' 'A-F')"

# Option C: Random corporate-style
COMPANY_PREFIXES=("corp-lap" "it-usr" "dev-box" "wkstn" "office")
NEW_HOSTNAME="${COMPANY_PREFIXES[$RANDOM % ${#COMPANY_PREFIXES[@]}]}-$(shuf -i 100-999 -n1)"

# Apply the new hostname
sudo hostnamectl set-hostname "$NEW_HOSTNAME"

# Update /etc/hosts
sudo sed -i "s/^127.0.1.1.*/127.0.1.1 $NEW_HOSTNAME/" /etc/hosts

# Verify
hostnamectl status
hostname
cat /etc/hostname

# ═══════════════════════════════════════════════════════════
# 6. MACHINE-ID ROTATION
# ═══════════════════════════════════════════════════════════
# Machine ID identifies the system to many services (DHCP, D-Bus, etc.)
sudo rm /etc/machine-id
sudo systemd-machine-id-setup

# Also rotate the D-Bus machine ID if it exists
if [ -f /var/lib/dbus/machine-id ]; then
    sudo rm /var/lib/dbus/machine-id
    sudo ln -s /etc/machine-id /var/lib/dbus/machine-id
fi

# Verify new machine ID
cat /etc/machine-id
```

## OPSEC Rules

- **MAC randomization is detected by NAC**: Network Access Control systems flag rapid MAC changes — change before connecting, not during
- Interface goes down briefly during MAC change — do not do this mid-active-scan
- Hostname changes are logged by systemd-journald — clear journalctl if needed
- Machine-id rotation breaks D-Bus sessions — do before starting engagement, not mid-session
- Some corporate 802.1X environments tie MAC to certificate — MAC change breaks authenticated access
- Do NOT use completely random OUI (00:00:00 or unassigned ranges) — they flag as spoofed on network scans
- Rotate MAC addresses between networks (different coffee shop, different MAC)
- Keep a log of which MAC you used where — helps if defenders correlate across locations
- Wireless MAC randomization using NetworkManager's `random` setting is detectable by deauth patterns

## Verification

- [ ] `macchanger -s eth0` shows new MAC with expected OUI prefix
- [ ] `ip link show eth0` confirms the new MAC is active
- [ ] `hostnamectl status` shows the new random hostname
- [ ] `cat /etc/machine-id` shows different ID than before
- [ ] Network connectivity is restored after the change (ping gateway)
- [ ] DHCP assigned a new IP after MAC change

## Pitfalls

- **Virtual machines** inherit MAC from hypervisor — spoofed MAC may conflict with VM configuration
- **Docker containers** share host network namespace — MAC spoofing on host affects all containers
- **Wake-on-LAN** relies on fixed MAC — breaks if MAC is randomized
- **NetworkManager** may override `macchanger` changes on reconnect — disable NM control: `nmcli dev set eth0 managed no`
- **VLAN tagging** depends on port configuration — MAC change does not affect VLAN but some switches bind MAC to VLAN
- **MAC randomization on Wi-Fi**: Some drivers don't support custom MACs — check with `ethtool -P eth0`
- **IPv6 SLAAC**: New MAC generates new IPv6 address via modified EUI-64 — may leak old association
- **Network scripts**: Custom `/etc/network/interfaces` configs may ignore macchanger changes

## Output Format

```json
{
  "skill": "anonymity-macchanger",
  "interface": "eth0",
  "original_mac": "aa:bb:cc:dd:ee:ff",
  "new_mac": "00:1b:21:12:34:56",
  "vendor_oui": "Intel",
  "old_hostname": "original-pc",
  "new_hostname": "DESKTOP-A1B2C3D4",
  "machine_id_rotated": true,
  "status": "complete",
  "resolved_at": "2026-07-13T12:00:00Z"
}
```
