#!/usr/bin/env python3
"""
HoneyTrap (Credential Capture Edition)
Captures login credentials on multiple ports

WARNING: Educational purposes only!
This is a standalone version with hardcoded configuration.
"""

import socket
import threading
import logging
import json
import os
from datetime import datetime


# =============================================================================
# HARDCODED CONFIGURATION
# =============================================================================

HOST = '0.0.0.0'
PORTS = [2222, 8022, 2022]
LOG_FILE = 'logs/honeytrap.log'
CREDENTIALS_FILE = 'logs/credentials.json'


# =============================================================================
# SETUP LOGGING
# =============================================================================

os.makedirs('logs', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('HoneyTrap')


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def log_credentials(ip: str, port: int, username: str, password: str) -> None:
    """
    Log captured credentials to JSON file.
    
    Args:
        ip: Source IP address
        port: Target port that was attacked
        username: Captured username
        password: Captured password
    """
    with open(CREDENTIALS_FILE, 'a') as f:
        entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': ip,
            'target_port': port,
            'username': username,
            'password': password
        }
        f.write(json.dumps(entry) + '\n')


def handle_client(client_socket: socket.socket, address: tuple, port: int) -> None:
    """
    Handle client connection with fake login prompt.
    
    Args:
        client_socket: The client socket
        address: Tuple of (IP, source_port)
        port: The honeypot port that received the connection
    """
    ip = address[0]
    logger.warning(f"🚨 CAUGHT on port {port} from {ip}:{address[1]}")
    
    try:
        client_socket.settimeout(60)
        
        # Send fake SSH banner
        client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")
        
        # Wait for client banner
        client_socket.recv(1024)
        
        # Fake login prompt to trick simple bots
        client_socket.send(b"\r\n")
        client_socket.send(b"Welcome to Ubuntu 18.04.5 LTS\r\n")
        client_socket.send(b"\r\n")
        
        # Capture credentials
        client_socket.send(b"login: ")
        username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        client_socket.send(b"Password: ")
        password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        # Log the captured credentials
        if username or password:
            logger.critical(f"🔑 CREDENTIALS on port {port} from {ip}: {username}:{password}")
            log_credentials(ip, port, username, password)
        
        # Fake authentication failure
        client_socket.send(b"\r\nLogin incorrect\r\n")
        
    except socket.timeout:
        logger.info(f"⏱️ Connection on port {port} from {ip} timed out")
    except Exception as e:
        logger.error(f"Error on port {port}: {e}")
    finally:
        client_socket.close()
        logger.info(f"🔌 Released {ip} from port {port}")


def start_listener(port: int) -> None:
    """
    Start a listener on a specific port.
    
    Args:
        port: The port number to listen on
    """
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.listen(100)
        
        logger.info(f"🪤 Trap set on {HOST}:{port}")
        
        while True:
            try:
                client, address = server.accept()
                thread = threading.Thread(
                    target=handle_client,
                    args=(client, address, port),
                    daemon=True
                )
                thread.start()
            except socket.error:
                logger.error(f"Socket error on port {port}")
                
    except PermissionError:
        logger.error(f"Permission denied for port {port}. Need root/admin for ports < 1024.")
    except OSError as e:
        logger.error(f"Could not bind to port {port}: {e}")


def print_banner() -> None:
    """Print the startup banner."""
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
    """Main entry point."""
    print_banner()
    
    print(f"  Host: {HOST}")
    print(f"  Ports: {PORTS}")
    print(f"  Log File: {LOG_FILE}")
    print(f"  Credentials: {CREDENTIALS_FILE}")
    print()
    
    logger.info(f"🍯 HoneyTrap starting on {len(PORTS)} port(s)...")
    
    # Start a listener thread for each port
    threads = []
    for port in PORTS:
        thread = threading.Thread(target=start_listener, args=(port,), daemon=True)
        thread.start()
        threads.append(thread)
    
    logger.info("Waiting for prey... (Press Ctrl+C to stop)")
    
    # Keep main thread alive
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        logger.info("\n🛑 Shutting down HoneyTrap...")


if __name__ == "__main__":
    main()