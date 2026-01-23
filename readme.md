# 🍯 HoneyTrap 🪤

A Python-based multi-port honeypot that attracts and logs intrusion attempts. Built for learning cybersecurity concepts hands-on.

## What's This About?

Ever wondered how hackers try to break into servers? This project lets you watch it happen in real-time (safely). 

HoneyTrap pretends to be a vulnerable server. When attackers connect, thinking they found an easy target, we silently log everything they do. It's like setting up a security camera for your network.

## Features

- **Multi-port listening** - Monitor multiple ports simultaneously (2222, 8022, 2022, etc.)
- **Credential capture** - Optional advanced mode that logs usernames and passwords
- **Detailed logging** - JSON + text logs with timestamps, IPs, and raw data
- **Docker support** - One command deployment with docker-compose
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Zero dependencies** - Pure Python standard library

## Quick Start

### Option 1: Run directly

```bash
git clone https://github.com/thekoolk15/HoneyTrap.git
cd HoneyTrap
mkdir -p logs
python honeytrap.py
```

### Option 2: Run with Docker

```bash
git clone https://github.com/thekoolk15/HoneyTrap.git
cd HoneyTrap
docker-compose up -d --build
docker-compose logs -f
```

## Project Structure

```
HoneyTrap/
├── honeytrap.py              # Main honeypot
├── honeytrap_with_creds.py   # Credential capture version
├── config.py                 # Configuration settings
├── analyzer.py               # Log analysis tool
├── Dockerfile                # Docker image definition
├── docker-compose.yml        # Docker compose config
├── requirements.txt          # Dependencies (none required!)
└── logs/                     # Attack logs stored here
```

## Two Flavors

### Basic (`honeytrap.py`)
Low-interaction honeypot. Logs connections and SSH handshake data. Safe and simple.

```bash
python honeytrap.py
```

### Advanced (`honeytrap_with_creds.py`)
Fakes a login prompt to capture credentials. Standalone with hardcoded config.

```bash
python honeytrap_with_creds.py
```

## Configuration

Edit `config.py` to customize:

```python
HOST = '0.0.0.0'              # Listen on all interfaces
PORTS = [2222, 8022, 2022]    # Add or remove ports as needed
FAKE_SSH_BANNER = 'SSH-2.0-OpenSSH_7.4\r\n'  # What attackers see
```

### Port Ideas

| Port | Why Use It |
|------|------------|
| 22 | The real deal (needs root) |
| 2222 | Classic alternative |
| 8022 | Looks like Docker SSH |
| 2022 | Subtle, less suspicious |

## 🐳 Docker Deployment

### Start the honeypot

```bash
docker-compose up -d --build
```

### View live logs

```bash
docker-compose logs -f
```

### Stop the honeypot

```bash
docker-compose down
```

### Run credential capture version in Docker

```bash
docker run -d \
  --name honeytrap-creds \
  -p 2222:2222 \
  -p 8022:8022 \
  -p 2022:2022 \
  -v $(pwd)/logs:/app/logs \
  ssh-honeypot-honeytrap \
  python honeytrap_with_creds.py
```

## Testing Locally

Terminal 1:
```bash
python honeytrap.py
# or
docker-compose up
```

Terminal 2:
```bash
nc localhost 2222
# or
ssh anything@localhost -p 2222
```

Watch the logs light up! 🎆

## Analyzing Attacks

After collecting some data:

```bash
python analyzer.py --json
```

You'll get a breakdown of:
- Top attacking IPs
- Attacks per port
- Attack frequency by hour
- Captured data samples

## What You'll Learn

- Socket programming in Python
- Multi-threaded network servers
- How SSH handshakes work
- Real attack patterns and techniques
- Security logging best practices
- Docker containerization

## Sample Output

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

## Going Public?

If you deploy this on a real server (AWS, DigitalOcean, etc.), you'll see actual attack traffic within minutes. The internet is a wild place.

**But first:**
- Use an isolated VM or container
- Don't put this on a production network
- Check local laws about monitoring network traffic
- Keep your actual SSH on a different, non-standard port

## Roadmap

- [x] Multi-port SSH honeypot
- [x] Credential capture mode
- [x] Log analyzer
- [x] Docker support
- [ ] FTP honeypot
- [ ] Telnet honeypot
- [ ] Web dashboard
- [ ] IP geolocation
- [ ] Real-time alerts

## Resources

- [Cowrie](https://github.com/cowrie/cowrie) - Production-grade SSH honeypot
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots) - Community list of honeypot tools
- [The Honeynet Project](https://www.honeynet.org/) - Research org behind honeypot tech

## License

MIT - Do whatever you want with it. Learn something cool.

---

*Set the trap. Catch the prey.* 🪤