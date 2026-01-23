"""
Configuration settings for HoneyTrap.

Modify these settings to customize the honeypot behavior.
All sensitive settings should be reviewed before deployment.
"""

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

# Host address to bind to
# '0.0.0.0' = Listen on all network interfaces (accessible from network)
# '127.0.0.1' = Listen only on localhost (for testing)
HOST = '0.0.0.0'

# Ports to listen on (can be single port or multiple)
# Examples:
#   PORTS = [2222]                    # Single port
#   PORTS = [22, 2222, 8022]          # Multiple ports
#   PORTS = [22, 2222, 2022, 8022]    # Even more ports
PORTS = [2222, 8022, 2022]

# Maximum number of queued connections per port
MAX_CONNECTIONS = 100


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Path to the log file (relative to script location)
LOG_FILE = 'logs/honeytrap.log'

# Enable JSON logging for easier parsing and analysis
# Creates a .json file alongside the regular log
ENABLE_JSON_LOGGING = True


# =============================================================================
# DECEPTION CONFIGURATION
# =============================================================================

# Fake SSH banner to present to attackers
# This makes the honeypot appear as a real SSH server
# Format: SSH-<protocol version>-<software version> <comments>
# 
# Common banners to mimic (choose one for realism):
# - 'SSH-2.0-OpenSSH_7.4\r\n'  (older, potentially vulnerable)
# - 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n'  (Ubuntu server)
# - 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n'  (Debian server)
FAKE_SSH_BANNER = 'SSH-2.0-OpenSSH_7.4\r\n'


# =============================================================================
# SECURITY NOTES
# =============================================================================
"""
IMPORTANT SECURITY CONSIDERATIONS:

1. ISOLATION: Always run HoneyTrap in an isolated environment
   (VM, container, or dedicated machine) to prevent lateral movement
   if somehow compromised.

2. LEGAL: Only deploy on networks you own or have explicit permission
   to monitor. Unauthorized monitoring may violate laws.

3. PRODUCTION: This is a LOW-interaction honeypot for learning.
   For production use, consider additional hardening.

4. MONITORING: Regularly review logs and set up alerts for suspicious
   activity patterns.

5. UPDATES: Keep your system and Python packages updated to prevent
   vulnerabilities in the honeypot itself.

6. PRIVILEGED PORTS: Ports below 1024 (like 22) require root/admin
   privileges to bind to.
"""