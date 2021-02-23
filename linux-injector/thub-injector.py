#!/usr/bin/python3

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
CAPTURER_INFORM_MESSAGE = b'HOSTC'   # Hub Output - Socket Type Capturer
INJECTOR_INFORM_MESSAGE = b'HOSTI'   # Hub Output - Socket Type Injector


debug = False


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


def display_packet_info(packet, direction):
    src_mac_address = packet[6:12]
    dst_mac_address = packet[0:6]
    parsed_src_address = ":".join([hex(i)[2:] if len(hex(i)) == 4 else '0'+hex(i)[2:] for i in src_mac_address])
    parsed_dst_address = ":".join([hex(i)[2:] if len(hex(i)) == 4 else '0'+hex(i)[2:] for i in dst_mac_address])
    print(f"[*] {direction} Packet from {parsed_src_address} to {parsed_dst_address}, packet length: {len(packet)}")


def communicate_loop(device, injector_client_socket, capturer_client_socket):
    global debug
    while True:
        should_sleep = True
        # Read from tap and write to server socket
        if device.is_ready_to_read():
            packet, sender = device.read_packet()
            if debug:
                display_packet_info(packet, "Recieveing")
            send_packet(capturer_client_socket, packet)
            should_sleep = False
        # Read from server socket and write to tap
        ready_socket, _, _ = select.select([injector_client_socket], [], [], 0)
        if ready_socket:
            packet = read_packet(injector_client_socket)
            if debug:
                display_packet_info(packet, "Sending")
            device.send_packet(packet)
            should_sleep = False
        # Sleep to avoid busy loops
        if should_sleep:
            sleep(SLEEP_TIME_SEC)


def get_device_info(device):
    parsed_mac_address = ":".join([hex(i)[2:] if len(hex(i)) == 4 else '0'+hex(i)[2:] for i in device.mac_address])
    return f"\tMAC Address:\t{parsed_mac_address}\n\tIP Address:\t{device.ip}\n\tNetmask:\t{device.netmask}"


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
            print(f"[*] Created device: {device}")
            print(get_device_info(device))
            with Bridge(bridge_name) as bridge:
                bridge.add_interface(physical_interface_name)
                bridge.add_interface(device.tap_name)
                print(f"[*] You can start using {device.tap_name.decode()} now")
                init_client_injector_socket(injector_client_ssl)
                init_client_capturer_socket(capturer_client_ssl)
                try:
                    communicate_loop(device, injector_client_ssl, capturer_client_ssl)
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
    parser = argparse.ArgumentParser(description='VPH client')
    parser.add_argument('--config', '-c', help="Path to the config file", type=str, required=True)
    parser.add_argument('--debug', '-d', help="Display debug messges", action='store_true', required=False, default=False)
    return parser.parse_args()


def main():
    global debug
    args = parse_argumets()
    debug = args.debug
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
