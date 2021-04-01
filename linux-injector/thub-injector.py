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
from bridge import Bridge


SLEEP_TIME_SEC = 0.005
CAPTURER_INFORM_MESSAGE = b'TISTW' # THUB Injector - Socket Type Writer
INJECTOR_INFORM_MESSAGE = b'TISTR' # THUB Injector - Socket Type Reader


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


def communication_loop(device, injector_client_socket, capturer_client_socket):
    while True:
        should_sleep = True
        # Read from tap and write to server socket
        if device.is_ready_to_read():
            packet, sender = device.read_packet()
            send_packet(capturer_client_socket, packet)
            should_sleep = False
        # Read from server socket and write to tap
        ready_socket, _, _ = select.select([injector_client_socket], [], [], 0)
        if ready_socket:
            packet = read_packet(injector_client_socket)
            device.send_packet(packet)
            should_sleep = False
        # Sleep to avoid busy loops if no packets were sent
        if should_sleep:
            sleep(SLEEP_TIME_SEC)


def print_device_info(device):
    print(f"[*] Created device: {device}", end='\n\t')
    parsed_mac_address = ":".join([hex(i)[2:] if len(hex(i)) == 4 else '0'+hex(i)[2:] for i in device.mac_address])
    print("\n\t".join([f"MAC Address:\t{parsed_mac_address}",
                       f"IP Address:\t{device.ip}",
                       f"Netmask:\t{device.netmask}"]))


def create_ssl_socket(server_ip, server_port):
    client = socket.socket()
    client.connect((server_ip, server_port))
    ssl_socket = ssl.wrap_socket(client)
    return ssl_socket, client


def init_client_injector_socket(client):
    client.send(INJECTOR_INFORM_MESSAGE)


def init_client_capturer_socket(client):
    client.send(CAPTURER_INFORM_MESSAGE)


def main_loop(server_ip, server_port, bridge_name, physical_interface_name,
    tap_name, mac_address, ip_address, netmask):
    if tap_name is None:
        tap_name = b'\x00'
    if type(physical_interface_name) is str:
        physical_interface_name = physical_interface_name.encode()
    print(f"[*] Connecting to server:{server_ip}:{server_port}")
    capturer_client_ssl, capturer_client = create_ssl_socket(server_ip, server_port)
    injector_client_ssl, injector_client = create_ssl_socket(server_ip, server_port)
    try:
        with Tap(tap_name, ip_address, netmask, mac_address) as device:
            print_device_info(device)
            with Bridge(bridge_name) as bridge:
                print(f"[*] Created device: {bridge}")
                bridge.add_interface(physical_interface_name)
                bridge.add_interface(device.tap_name)
                init_client_injector_socket(injector_client_ssl)
                init_client_capturer_socket(capturer_client_ssl)
                try:
                    communication_loop(device, injector_client_ssl, capturer_client_ssl)
                finally:
                    print(f"\n[*] Closing tap device: {device}")
    finally:
        print("[*] Closing server connection!")
        # Close all sockets
        capturer_client_ssl.close()
        capturer_client.close()
        injector_client_ssl.close()
        injector_client.close()


def parse_argumets():
    parser = argparse.ArgumentParser(description='THUB Injector')
    parser.add_argument('--config', '-c', help="Path to the config file", type=str, required=True)
    return parser.parse_args()


def main():
    args = parse_argumets()
    if not os.path.isfile(args.config):
        print(f"Could not open the configuration file {args.config}")
        return
    with open(args.config) as conf_file:
        config = json.load(conf_file)
    main_loop(
        server_ip=config['server']['host'], server_port=config['server']['port'],
        bridge_name=config['bridge']['bridge_name'], physical_interface_name=config['bridge']['physical_interface_name'],
        tap_name=config['tap']['tap_name'], mac_address=config['tap']['mac_address'],
        ip_address=config['tap']['ip_address'], netmask=config['tap']['ip_netmask']
        )


if __name__ == '__main__':
    main()
