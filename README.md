# net_seal 🔒 — v1.0.1  
**NERON Intelligence Systems — Outbound Firewall Auto-Whitelisting Engine**

`net_seal` v1.0.1 is an automated egress-whitelisting engine developed under **NERON Intelligence Systems**.  
It learns your system’s legitimate outbound traffic in real time and generates a hardened `iptables` script that only allows those observed destinations and blocks everything else.

Lightweight. Fast. Secure.  
A NERON-internal product designed for hardened Linux systems, malware detonation labs, field assets, and autonomous perimeter sealing.

> “Record what I talk to right now, then seal the perimeter.”

---

## ✨ Features (v1.0.1)

- 📡 Live outbound TCP/UDP connection observation via `ss -tuna`
- 🔍 Automated outbound allowlist generation
- 🛡️ Hardened firewall script creation:
  - Loopback allowed  
  - Established/related allowed  
  - **DNS (TCP/UDP 53) is automatically allowed by default**  
    - These rules can be manually removed from the generated script if desired  
  - Captured IP:port pairs explicitly whitelisted  
  - Everything else dropped by default (unless `--no-drop`)
- ⚙️ Configurable parameters:
  - Observation duration  
  - Output script path  
  - Option to disable DROP mode
- 🧪 Ideal for:
  - Linux host hardening  
  - Air-gapped systems  
  - Kiosk or constrained-use environments  
  - Malware-analysis VMs  
  - NERON SecureOps prototypes

---

## 🧬 How It Works

1. `net_seal` monitors outbound traffic for a chosen number of seconds.  
2. It extracts unique remote IP:port destinations.  
3. It generates a hardened iptables lockdown script.  
4. You manually apply the script after reviewing.  

Nothing is applied automatically — full operator control.

---

## 📦 Requirements

- Linux  
- Python 3.6+  
- `ss` (from iproute2)  
- `iptables`

---

## 🚀 Usage

Run:

```bash
python3 net_seal.py [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--observe-seconds N` | Time to watch outbound traffic (default: 30s) |
| `--out filename` | Output iptables script location (default: rules_seal.sh) |
| `--no-drop` | Do not DROP all outbound traffic at the end |

---

## 📚 Examples

### Strict lockdown (recommended)

```bash
sudo python3 net_seal.py --observe-seconds 30
sudo bash rules_seal.sh
```

---

### Without DROP policy

```bash
sudo python3 net_seal.py --observe-seconds 45 --no-drop
```

---

### Custom output filename

```bash
sudo python3 net_seal.py --observe-seconds 60 --out neron_rules_v1.sh
```

---

## 📄 Example Generated Firewall Script (v1.0.1)

```sh
#!/bin/sh
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established / related
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS (automatically included by default)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Observed destinations (example)
iptables -A OUTPUT -p tcp -d 142.250.191.142 --dport 443 -j ACCEPT
iptables -A OUTPUT -p udp -d 192.0.2.14 --dport 123 -j ACCEPT

# Final lockdown
iptables -P OUTPUT DROP
```

---

## ⚠️ Safety Notes

- Anything not observed will be **blocked**.  
- VPNs, updates, messaging/sync apps may stop functioning.  
- Always review the generated script before executing it.  
- Maintain console or fallback access (SSH may be blocked).

---

## 👨‍💻 Code Source

`net_seal.py`  
A NERON Intelligence Systems internal security tool.

---

## 📄 License

MIT License

---

## 🔮 Roadmap (v1.1.x Planned)

- nftables backend  
- Rolling adaptive learning mode  
- Domain-aware rules (DNS classification)  
- YAML/JSON export  
- Undo/rollback generator  
- TUI interface  
- Integration with NERON SecureOps Suite  
