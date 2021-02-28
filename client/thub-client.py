#!/usr/bin/python3

import os
import ssl
import json
import socket
import select
import argparse
from time import sleep
from string import digits
from tap import Tap


SLEEP_TIME_SEC = 0.005
THUB_CLIENT_SOCKET_READ_WRITE = b'TCSRW'
CONTROL_SOCKET_UPDATE_MAC_ADDRESS = b'CSUMA'


def read_packet(client_socket):
    expected_packet_size = client_socket.recv(5)
    if expected_packet_size != b"":
        next_byte = 0
        while ((chr(expected_packet_size[0]) not in digits) and (next_byte != b"")):
            next_byte = client_socket.recv(1)
            expected_packet_size = expected_packet_size[1:] + next_byte
        if b'\x00' in expected_packet_size:
            expected_packet_size = int(expected_packet_size[:expected_packet_size.index(b'\x00')].decode())
        else:
            expected_packet_size = int(expected_packet_size.decode())
        return read_full_packet(client_socket, expected_packet_size)
    else:
        raise ConnectionResetError("The socket was closed while reading")


def read_full_packet(client_socket, expected_packet_size):
    full_packet = b""
    while len(full_packet) < expected_packet_size:
        packet = client_socket.recv(expected_packet_size - len(full_packet))
        if packet == b"":
            ConnectionResetError("The socket was closed while reading")
        full_packet += packet
    return full_packet


def prepare_packet(packet_data):
    packetlen = str(len(packet_data))
    packetlen = packetlen.encode() + (b'\x00' * (5 - len(packetlen)))
    return packetlen + packet_data


def send_packet(client_socket, packet):
    client_socket.sendall(prepare_packet(packet))


def inform_server_about_new_mac_address(client, new_mac):
    client.send(CONTROL_SOCKET_UPDATE_MAC_ADDRESS + new_mac)


def validate_send_mac_address(sender_address, device, client):
    if sender_address != device.mac_address:
        if device._check_if_mac_has_changed():
            inform_server_about_new_mac_address(client, device.mac_address)
        else:
            print("\n".join(["[!] Warning! Sending a packet with a mac address that differs from the device's address.",
                             "This can cause unexpected behaviour!"]))

def communication_loop(device, client_socket):
    while True:
        should_sleep = True
        ready_socket, _, _ = select.select([client_socket], [], [], 0)
        # Read from server socket and write to tap
        if ready_socket:
            packet = read_packet(client_socket)
            device.send_packet(packet)
            should_sleep = False
        # Read from tap and write to server socket
        if device.is_ready_to_read():
            packet, sender = device.read_packet()
            validate_send_mac_address(sender, device, client_socket)
            send_packet(client_socket, packet)
            should_sleep = False
        # Sleep to avoid busy loops if no packets were sent
        if should_sleep:
            sleep(SLEEP_TIME_SEC)


def print_new_device_info(device):
    print(f"[*] Created device: {device}", end='\n\t')
    parsed_mac_address = ":".join([hex(i)[2:] if len(hex(i)) == 4 else '0'+hex(i)[2:] for i in device.mac_address])
    print('\n\t'.join([f"MAC Address:\t{parsed_mac_address}",
                       f"IP Address:\t{device.ip}",
                       f"Netmask:\t{device.netmask}"]))
    print(f"[*] You can start using {device.tap_name.decode()} now")


def init_client_socket(client, mac_address):
    client.send(THUB_CLIENT_SOCKET_READ_WRITE)
    inform_server_about_new_mac_address(client, mac_address)


def main_loop(server_ip, server_port, tap_name, mac_address, ip_address, netmask):
    if tap_name is None:
        tap_name = b'\x00'
    print(f"[*] Connecting to server:{server_ip}:{server_port}")
    client = socket.socket()
    client.connect((server_ip, server_port))
    ssl_socket = ssl.wrap_socket(client)
    try:
        with Tap(tap_name, ip_address, netmask, mac_address) as device:
            print_new_device_info(device)
            init_client_socket(ssl_socket, device.mac_address)
            try:
                communication_loop(device, ssl_socket)
            finally:
                print(f"\n[*] Closing tap device: {device}")
    finally:
        print("[*] Closing server connection!")
        ssl_socket.close()
        client.close()


def parse_argumets():
    parser = argparse.ArgumentParser(description='THUB client')
    parser.add_argument('--config', '-c', help="Path to the config file", type=str, required=True)
    return parser.parse_args()


def main():
    args = parse_argumets()
    if not os.path.isfile(args.config):
        print(f"Could not open the configuration file {args.config}")
        return
    with open(args.config) as args.config:
        config = json.load(args.config)
    main_loop(
        server_ip=config['server']['host'], server_port=config['server']['port'],
        tap_name=config['client']['tap_name'], mac_address=config['client']['mac_address'],
        ip_address=config['client']['ip_address'], netmask=config['client']['ip_netmask'])


if __name__ == '__main__':
    main()
