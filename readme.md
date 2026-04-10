# 🍯 HoneyTrap 🪤

A multi-port SSH honeypot that attracts attackers and logs everything they do. Built with Python, zero external dependencies.

![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)
![MIT License](https://img.shields.io/badge/license-MIT-yellow)

## What's This About?

Ever wondered how hackers try to break into servers? HoneyTrap lets you watch it happen in real-time (safely).

It pretends to be a vulnerable SSH server. When attackers connect, thinking they found an easy target, we silently log everything they do. It's basically a security camera for your network.

Deploy it on a public server and you'll see real attack traffic within minutes. The internet is a wild place.

## Quick Start

### Run directly

```bash
git clone https://github.com/thekoolk15/HoneyTrap.git
cd HoneyTrap
python honeytrap.py
```

### Run with Docker

```bash
git clone https://github.com/thekoolk15/HoneyTrap.git
cd HoneyTrap
docker-compose up -d --build
docker-compose logs -f
```

## Features

- **Multi-port listening** — Monitor multiple ports at once (2222, 8022, 2022, etc.)
- **Credential capture** — Advanced mode that fakes a login prompt to grab usernames & passwords
- **SSH client detection** — Tells apart real SSH clients from simple bots so credential logs stay clean
- **Thread-safe logging** — Uses mutex locks so logs don't get corrupted when multiple attackers connect at once
- **Dual logging** — Human-readable `.log` files + machine-parseable JSON for analysis
- **Built-in analyzer** — CLI reporting tool for attack patterns, top IPs, hourly breakdown
- **Docker support** — One-command deployment with docker-compose
- **Zero dependencies** — Runs on Python standard library only

## How It Works

```
                    ┌─────────────────────────┐
                    │    Attacker / Scanner    │
                    └────────────┬────────────┘
                                 │ TCP connect
                    ┌────────────▼────────────┐
                    │    Socket Listeners      │
                    │  :2222  :8022  :2022     │
                    └────────────┬────────────┘
                                 │ accept() → spawn thread
                    ┌────────────▼────────────┐
                    │  Connection Handler      │
                    │  ┌────────────────────┐  │
                    │  │ Send SSH Banner    │  │
                    │  │ SSH-2.0-OpenSSH_7.4│  │
                    │  └────────┬───────────┘  │
                    │           │               │
                    │  ┌────────▼───────────┐  │
                    │  │ Capture & Log Data │  │
                    │  └────────┬───────────┘  │
                    └───────────┬──────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                  ▼
      honeytrap.log     honeytrap.json     credentials.json
       (human)           (machine)          (creds only)
              │                 │
              └────────┬────────┘
                       ▼
               analyzer.py 📊
```

## Two Flavors

### Basic (`honeytrap.py`)

Low-interaction honeypot. Logs connections and SSH handshake data. Simple and safe.

```bash
python honeytrap.py
```

### Credential Capture (`honeytrap_with_creds.py`)

This one goes a step further — it fakes a login prompt to trick bots into giving up their credentials:

```
SSH-2.0-OpenSSH_7.4
Welcome to Ubuntu 18.04.5 LTS

login: █
Password: █

Login incorrect
```

Captured creds get logged to `credentials.json`. Real SSH clients (that send binary KEX packets) are detected automatically and skipped — so you don't end up with garbled binary junk in your credential logs.

```bash
python honeytrap_with_creds.py
```

`CredentialHoneyTrap` is a subclass of `HoneyTrap` — it inherits the multi-port listener, thread-safe logging, and config. It only overrides the connection handler.

## Project Structure

```
HoneyTrap/
├── honeytrap.py              # Main honeypot (HoneyTrap class)
├── honeytrap_with_creds.py   # Credential capture version (subclass)
├── config.py                 # Configuration
├── analyzer.py               # Log analysis tool
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── logs/
    ├── honeytrap.log         # Text log
    ├── honeytrap.json        # JSON log
    └── credentials.json      # Captured credentials
```

## Configuration

Edit `config.py`:

```python
HOST = '0.0.0.0'                              # Listen on all interfaces
PORTS = [2222, 8022, 2022]                     # Ports to monitor
MAX_CONNECTIONS = 100                          # Backlog per port
LOG_FILE = 'logs/honeytrap.log'                # Log file path
CREDENTIALS_FILE = 'logs/credentials.json'     # Credential log
FAKE_SSH_BANNER = 'SSH-2.0-OpenSSH_7.4\r\n'   # Banner attackers see
ENABLE_JSON_LOGGING = True                     # JSON logging on/off
```

### Banner Ideas

Pick a banner that looks like a real (slightly outdated) server:

| Banner | Looks Like |
|--------|-----------|
| `SSH-2.0-OpenSSH_7.4` | CentOS/RHEL 7 (default) |
| `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1` | Ubuntu 20.04 |
| `SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2` | Debian 10 |
| `SSH-2.0-OpenSSH_6.6.1` | Old and tempting |

### Port Ideas

| Port | Why |
|------|-----|
| 22 | Standard SSH (needs root) |
| 2222 | Classic alternative |
| 8022 | Looks like Docker SSH |
| 2022 | Subtle |

## Testing Locally

**Terminal 1** — Start the honeypot:
```bash
python honeytrap.py
```

**Terminal 2** — Poke it:
```bash
# Plain TCP
nc localhost 2222

# SSH
ssh anything@localhost -p 2222
```

### Sample Output

```
🍯 HoneyTrap starting on 3 port(s)...
🪤 Trap set on 0.0.0.0:2222
🪤 Trap set on 0.0.0.0:8022
🪤 Trap set on 0.0.0.0:2022
Waiting for prey... (Press Ctrl+C to stop)

🚨 CAUGHT on port 2222 from 192.168.1.50:58432
📥 Data on port 2222 from 192.168.1.50: 'SSH-2.0-OpenSSH_10.0\r\n'
⏱️ Connection on port 2222 from 192.168.1.50 timed out
🔌 Released 192.168.1.50:58432 from port 2222
```

## 🐳 Docker

```bash
# Start
docker-compose up -d --build

# Watch logs
docker-compose logs -f

# Stop
docker-compose down
```

Run the credential version in Docker:

```bash
docker run -d \
  --name honeytrap-creds \
  -p 2222:2222 -p 8022:8022 -p 2022:2022 \
  -v $(pwd)/logs:/app/logs \
  ssh-honeypot-honeytrap \
  python honeytrap_with_creds.py
```

## Analyzing Attacks

```bash
python analyzer.py --json
```

Gives you top attacking IPs, attacks per port, hourly breakdown, captured data samples, and some insights (like flagging IPs with too many attempts).

## What You'll Learn

- Socket programming in Python
- Multi-threaded servers and thread safety
- How SSH handshakes and key exchange work
- Real-world attack patterns
- Structured logging for security analysis
- Docker containerization
- OOP — class inheritance for extensible tools

## ⚠️ Heads Up

If you deploy this on a real server, you'll get actual attacks fast. Be smart about it:

- Use an isolated VM or container
- Don't run this on a production network
- Keep your real SSH on a different port
- Check your local laws about network monitoring
- This is a low-interaction honeypot — for prod use check out [Cowrie](https://github.com/cowrie/cowrie)

## Roadmap

- [x] Multi-port SSH honeypot
- [x] Credential capture mode
- [x] SSH client detection
- [x] Thread-safe logging
- [x] Log analyzer
- [x] Docker support
- [ ] FTP honeypot
- [ ] Telnet honeypot
- [ ] Web dashboard
- [ ] IP geolocation
- [ ] Real-time alerts
- [ ] Log rotation

## Resources

- [Cowrie](https://github.com/cowrie/cowrie) — Production-grade SSH honeypot
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots) — Curated honeypot list
- [The Honeynet Project](https://www.honeynet.org/) — Research org behind honeypot tech
- [T-Pot](https://github.com/telekom-security/tpotce) — Multi-honeypot platform

## License

MIT — do whatever you want with it.

---

*Set the trap. Catch the prey. 🪤*