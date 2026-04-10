#!/usr/bin/env python3
"""
HoneyTrap (Credential Capture Edition)

Extends the base HoneyTrap to capture login credentials.
This version overrides the connection handler to present a fake
login prompt and capture credentials from simple TCP clients and bots.

SSH clients sending binary KEX_INIT packets are detected and logged
separately without attempting credential capture.
"""

import socket
import json
from datetime import datetime

from honeytrap import HoneyTrap
from config import HOST, PORTS, LOG_FILE, CREDENTIALS_FILE


class CredentialHoneyTrap(HoneyTrap):
    """
    Extended honeypot that captures login credentials.

    Inherits all multi-port listening and logging from HoneyTrap,
    but overrides connection handling to present a fake login prompt
    and capture credentials from simple TCP clients and bots.

    Real SSH clients (which send "SSH-2.0-..." version strings followed
    by binary KEX_INIT data) are detected and logged separately without
    credential capture attempts.
    """

    def _handle_connection(self, client_socket: socket.socket,
                           client_address: tuple, port: int) -> None:
        """
        Handle client connection with fake login prompt.

        Detects real SSH clients (which send SSH-2.0 version strings)
        and logs them without attempting credential capture. For plain
        TCP clients (netcat, simple bots), presents a fake Ubuntu login
        prompt to capture usernames and passwords.

        Args:
            client_socket: The socket object for this connection
            client_address: Tuple of (IP address, port) of the client
            port: The honeypot port that received the connection
        """
        ip, src_port = client_address

        # Log the connection attempt
        self.logger.warning(f"🚨 CAUGHT on port {port} from {ip}:{src_port}")

        self._log_json('connection', {
            'target_port': port,
            'source_ip': ip,
            'source_port': src_port,
            'status': 'connected'
        })

        try:
            client_socket.settimeout(60)

            # Send fake SSH banner to appear as a real SSH server
            client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")

            # Wait for client response (SSH banner or plain text)
            client_data = client_socket.recv(1024)

            if not client_data:
                return

            # Detect real SSH clients by checking for SSH version string.
            # Real SSH clients respond with "SSH-2.0-..." and then send
            # binary KEX_INIT data. Attempting to capture that binary data
            # as credentials produces garbage — so we log and skip instead.
            if client_data.strip().startswith(b'SSH-'):
                decoded = client_data.decode('utf-8', errors='replace').strip()
                self.logger.info(
                    f"🔍 SSH client detected on port {port} from {ip}: {decoded}"
                )
                self._log_json('ssh_client_detected', {
                    'target_port': port,
                    'source_ip': ip,
                    'client_banner': decoded
                })
                return

            # Plain TCP client (netcat, bot) — proceed with fake login
            client_socket.send(b"\r\n")
            client_socket.send(b"Welcome to Ubuntu 18.04.5 LTS\r\n")
            client_socket.send(b"\r\n")

            # Capture credentials
            client_socket.send(b"login: ")
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

            client_socket.send(b"Password: ")
            password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

            # Log captured credentials
            if username or password:
                self.logger.critical(
                    f"🔑 CREDENTIALS on port {port} from {ip}: {username}:{password}"
                )
                self._log_credentials(ip, port, username, password)

            # Fake authentication failure
            client_socket.send(b"\r\nLogin incorrect\r\n")

        except socket.timeout:
            self.logger.info(f"⏱️ Connection on port {port} from {ip} timed out")
        except Exception as e:
            self.logger.error(f"Error on port {port} from {ip}: {e}")
        finally:
            client_socket.close()
            self.logger.info(f"🔌 Released {ip}:{src_port} from port {port}")

            self._log_json('connection', {
                'target_port': port,
                'source_ip': ip,
                'source_port': src_port,
                'status': 'disconnected'
            })

    def _log_credentials(self, ip: str, port: int,
                         username: str, password: str) -> None:
        """
        Log captured credentials to JSON file (thread-safe).

        Uses the parent class's lock to prevent concurrent write
        corruption from multiple connection handler threads.

        Args:
            ip: Source IP address
            port: Target port that was attacked
            username: Captured username
            password: Captured password
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': ip,
            'target_port': port,
            'username': username,
            'password': password
        }
        with self._log_lock:
            with open(CREDENTIALS_FILE, 'a') as f:
                f.write(json.dumps(entry) + '\n')


def print_banner() -> None:
    """Print the Credential Capture Edition startup banner."""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🍯 HONEYTRAP 🪤  [Credential Capture Edition]           ║
    ║                                                           ║
    ║   Multi-port | Captures credentials                       ║
    ║   For educational purposes only!                          ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def main():
    """Main entry point for the credential capture edition."""
    print_banner()

    print(f"  Host: {HOST}")
    print(f"  Ports: {PORTS}")
    print(f"  Log File: {LOG_FILE}")
    print(f"  Credentials: {CREDENTIALS_FILE}")
    print()

    # Create and start the credential capture honeypot
    trap = CredentialHoneyTrap()
    trap.start()


if __name__ == "__main__":
    main()