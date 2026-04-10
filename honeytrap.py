#!/usr/bin/env python3
"""
HoneyTrap - A multi-port intrusion detection honeypot
Author: thekoolk15
Purpose: Cybersecurity learning and attack analysis

HoneyTrap simulates vulnerable services to attract and log
connection attempts from potential attackers.

WARNING: For educational purposes only. Deploy responsibly
and only on networks you own or have permission to monitor.
"""

import socket
import threading
import logging
import json
import os
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from config import (
    HOST, PORTS, MAX_CONNECTIONS, LOG_FILE,
    FAKE_SSH_BANNER, ENABLE_JSON_LOGGING,
    MAX_THREADS, MAX_CONNECTIONS_PER_IP,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT
)


# Strip ANSI escapes and control characters from attacker data
# before writing to logs (prevents terminal escape injection)
_CONTROL_CHAR_RE = re.compile(
    r'\x1b\[[0-9;]*[a-zA-Z]'               # ANSI CSI sequences  (match first)
    r'|\x1b\][^\x07]*\x07'                  # OSC sequences
    r'|\x1b[()][A-Z0-9]'                    # Character set sequences
    r'|\x1b[^[\]()a-zA-Z]?'                 # Any other ESC sequence
    r'|[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]'  # C0 controls (skip ESC, keep \t \n \r)
)


class HoneyTrap:
    """
    A multi-port honeypot that simulates vulnerable services.

    This class creates fake servers that:
    - Listen for incoming connections on multiple ports
    - Present realistic banners to attackers
    - Log all connection attempts with detailed information
    - Capture any data sent by the attacker

    Attributes:
        host (str): The IP address to bind to
        ports (list): List of port numbers to listen on
        running (bool): Flag to control the server loop
        server_sockets (dict): Dictionary of port -> socket mappings
    """

    def __init__(self, host: str = HOST, ports: list = PORTS):
        """
        Initialize HoneyTrap with host and port settings.

        Args:
            host: IP address to bind to (default: 0.0.0.0 for all interfaces)
            ports: List of port numbers to listen on
        """
        self.host = host
        self.ports = ports
        self.server_sockets = {}
        self.running = False
        self._log_lock = threading.Lock()

        # Rate limiting: track active connections per IP
        self._ip_connections = defaultdict(int)
        self._ip_lock = threading.Lock()

        # Thread pool semaphore: cap total concurrent handler threads
        self._thread_semaphore = threading.Semaphore(MAX_THREADS)

        # Restrict file permissions (owner read/write only)
        os.umask(0o077)

        self._setup_logging()

    def _setup_logging(self) -> None:
        """
        Configure logging to capture all connection attempts.

        Sets up both file and console logging with timestamps
        for comprehensive attack monitoring. Uses rotating file
        handler to prevent disk exhaustion from accumulated logs.
        """
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)

        # Configure logging format with timestamp, level, and message
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'

        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            datefmt=date_format,
            handlers=[
                # Rotating file handler: auto-rotates when file hits size limit
                RotatingFileHandler(
                    LOG_FILE,
                    maxBytes=LOG_MAX_BYTES,
                    backupCount=LOG_BACKUP_COUNT
                ),
                # Also log to console for real-time monitoring
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('HoneyTrap')

    def _log_json(self, event_type: str, data: dict) -> None:
        """
        Log events in JSON format for easier analysis.

        Args:
            event_type: Type of event (connection, data_received, etc.)
            data: Dictionary containing event details
        """
        if ENABLE_JSON_LOGGING:
            json_log_file = LOG_FILE.replace('.log', '.json')
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                **data
            }
            with self._log_lock:
                self._rotate_json_log(json_log_file)
                with open(json_log_file, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')

    def _rotate_json_log(self, filepath: str) -> None:
        """
        Rotate JSON log file if it exceeds the size limit.
        Must be called while holding self._log_lock.

        Args:
            filepath: Path to the JSON log file
        """
        try:
            if os.path.exists(filepath) and os.path.getsize(filepath) > LOG_MAX_BYTES:
                # Shift existing backups: .4 -> .5, .3 -> .4, etc.
                for i in range(LOG_BACKUP_COUNT - 1, 0, -1):
                    src = f"{filepath}.{i}"
                    dst = f"{filepath}.{i + 1}"
                    if os.path.exists(src):
                        os.rename(src, dst)
                # Rotate current file to .1
                os.rename(filepath, f"{filepath}.1")
        except OSError:
            pass

    @staticmethod
    def _sanitize(text: str, max_length: int = 500) -> str:
        """
        Sanitize attacker-controlled text before logging.

        Strips ANSI escape sequences and control characters
        that could hijack a terminal when logs are viewed.
        Also caps length to prevent log flooding.

        Args:
            text: Raw decoded text from attacker
            max_length: Maximum characters to keep

        Returns:
            Sanitized string safe for logging and terminal display
        """
        cleaned = _CONTROL_CHAR_RE.sub('', text)
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length] + '...[truncated]'
        return cleaned

    def _check_rate_limit(self, ip: str) -> bool:
        """
        Check if an IP has exceeded the connection rate limit.

        Args:
            ip: Source IP address to check

        Returns:
            True if the connection should be allowed, False if rate limited
        """
        with self._ip_lock:
            if self._ip_connections[ip] >= MAX_CONNECTIONS_PER_IP:
                return False
            self._ip_connections[ip] += 1
            return True

    def _release_ip_slot(self, ip: str) -> None:
        """
        Release a connection slot for an IP when the connection ends.

        Args:
            ip: Source IP address to release
        """
        with self._ip_lock:
            self._ip_connections[ip] = max(0, self._ip_connections[ip] - 1)
            # Clean up IPs with no active connections
            if self._ip_connections[ip] == 0:
                del self._ip_connections[ip]

    def _start_listener(self, port: int) -> None:
        """
        Start a listener on a specific port.

        Args:
            port: The port number to listen on
        """
        try:
            # Create TCP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow socket reuse to avoid "Address already in use" errors
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to host and port
            server_socket.bind((self.host, port))

            # Start listening with specified backlog
            server_socket.listen(MAX_CONNECTIONS)

            # Store socket reference
            self.server_sockets[port] = server_socket

            self.logger.info(f"🪤 Trap set on {self.host}:{port}")

            self._log_json('listener_start', {
                'host': self.host,
                'port': port
            })

            # Accept connections on this port
            while self.running:
                try:
                    client_socket, client_address = server_socket.accept()
                    ip = client_address[0]

                    # Rate limit: check per-IP connection count
                    if not self._check_rate_limit(ip):
                        self.logger.warning(
                            f"⛔ Rate limited {ip} on port {port} "
                            f"(>{MAX_CONNECTIONS_PER_IP} concurrent)"
                        )
                        client_socket.close()
                        continue

                    # Thread pool limit: check global thread cap
                    if not self._thread_semaphore.acquire(blocking=False):
                        self.logger.warning(
                            f"⛔ Thread pool full, dropping {ip}:{client_address[1]} on port {port}"
                        )
                        self._release_ip_slot(ip)
                        client_socket.close()
                        continue

                    # Handle connection in a new thread
                    client_thread = threading.Thread(
                        target=self._handle_connection_wrapper,
                        args=(client_socket, client_address, port),
                        daemon=True
                    )
                    client_thread.start()

                except socket.error:
                    if self.running:
                        self.logger.error(f"Socket error on port {port}")

        except PermissionError:
            self.logger.error(f"Permission denied for port {port}. Ports below 1024 require root/admin.")
        except OSError as e:
            self.logger.error(f"Could not start listener on port {port}: {e}")

    def _handle_connection_wrapper(self, client_socket: socket.socket,
                                   client_address: tuple, port: int) -> None:
        """
        Wrapper that handles connection cleanup for rate limiting and thread pool.

        Calls the actual _handle_connection and ensures the IP slot
        and thread semaphore are released when the connection ends.
        """
        try:
            self._handle_connection(client_socket, client_address, port)
        finally:
            self._release_ip_slot(client_address[0])
            self._thread_semaphore.release()

    def start(self) -> None:
        """
        Start HoneyTrap on all configured ports.

        This method:
        1. Sets the running flag
        2. Spawns a listener thread for each port
        3. Waits for keyboard interrupt to stop
        """
        try:
            self.running = True

            self.logger.info(f"🍯 HoneyTrap starting on {len(self.ports)} port(s)...")

            self._log_json('server_start', {
                'host': self.host,
                'ports': self.ports
            })

            # Start a listener thread for each port
            listener_threads = []
            for port in self.ports:
                thread = threading.Thread(
                    target=self._start_listener,
                    args=(port,),
                    daemon=True
                )
                thread.start()
                listener_threads.append(thread)

            self.logger.info("Waiting for prey... (Press Ctrl+C to stop)")

            # Keep main thread alive
            while self.running:
                try:
                    threading.Event().wait(1)
                except KeyboardInterrupt:
                    break

        except KeyboardInterrupt:
            self.logger.info("\n🛑 Shutting down HoneyTrap...")
        finally:
            self.stop()

    def stop(self) -> None:
        """
        Gracefully stop HoneyTrap.

        Closes all server sockets and sets the running flag to False.
        """
        self.running = False

        # Close all server sockets
        for port, sock in self.server_sockets.items():
            try:
                sock.close()
                self.logger.info(f"Closed trap on port {port}")
            except Exception:
                pass

        self.logger.info("HoneyTrap stopped.")
        self._log_json('server_stop', {})

    def _handle_connection(self, client_socket: socket.socket,
                           client_address: tuple, port: int) -> None:
        """
        Handle an individual client connection.

        This method:
        1. Logs the connection attempt with client IP, port, and target port
        2. Sends a fake SSH banner to appear legitimate
        3. Receives and logs any data sent by the attacker
        4. Simulates authentication failure

        Args:
            client_socket: The socket object for this connection
            client_address: Tuple of (IP address, port) of the client
            port: The honeypot port that received the connection
        """
        ip_address, src_port = client_address

        # Log the connection attempt with target port info
        self.logger.warning(f"🚨 CAUGHT on port {port} from {ip_address}:{src_port}")

        self._log_json('connection', {
            'target_port': port,
            'source_ip': ip_address,
            'source_port': src_port,
            'status': 'connected'
        })

        received_data = bytearray()

        try:
            # Set a timeout to prevent hanging connections
            client_socket.settimeout(30)

            # Send fake SSH banner to make it look like a real SSH server
            client_socket.send(FAKE_SSH_BANNER.encode('utf-8'))

            # Receive data from the attacker
            try:
                while True:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    received_data.extend(chunk)

                    # Log received data (sanitized)
                    decoded = chunk.decode('utf-8', errors='replace')
                    sanitized = self._sanitize(decoded)
                    self.logger.info(
                        f"📥 Data on port {port} from {ip_address}: {repr(sanitized)}"
                    )

                    self._log_json('data_received', {
                        'target_port': port,
                        'source_ip': ip_address,
                        'data': chunk.hex(),
                        'data_decoded': self._sanitize(decoded, max_length=1000)
                    })

                    # Limit data collection
                    if len(received_data) > 4096:
                        break

            except socket.timeout:
                self.logger.info(f"⏱️ Connection on port {port} from {ip_address} timed out")

        except Exception as e:
            self.logger.error(f"Error handling connection from {ip_address}: {e}")

        finally:
            client_socket.close()
            self.logger.info(f"🔌 Released {ip_address}:{src_port} from port {port}")

            self._log_json('connection', {
                'target_port': port,
                'source_ip': ip_address,
                'source_port': src_port,
                'status': 'disconnected',
                'total_data_bytes': len(received_data)
            })


def print_banner() -> None:
    """Print the HoneyTrap ASCII banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🍯 HONEYTRAP 🪤                                         ║
    ║                                                           ║
    ║   Multi-port intrusion detection system                   ║
    ║   For educational purposes only!                          ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point for HoneyTrap."""
    print_banner()

    # Display configuration
    print(f"  Host: {HOST}")
    print(f"  Ports: {PORTS}")
    print(f"  Log File: {LOG_FILE}")
    print(f"  Max Threads: {MAX_THREADS}")
    print(f"  Max Per IP: {MAX_CONNECTIONS_PER_IP}")
    print()

    # Create and start HoneyTrap
    trap = HoneyTrap()
    trap.start()


if __name__ == "__main__":
    main()