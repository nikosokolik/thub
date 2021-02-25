#!/usr/bin/python3

import ssl
import queue
import select
import random
import argparse
import socketserver
from os import path
from time import sleep
from string import digits
from threading import Lock


SLEEP_TIME_SEC = 0.005
MAC_ADDRESS_LENGTH = 6
DEFAULT_SERVER_KEY = "server.key"
DEFAULT_SERVER_CERT = "server.crt"
DEFAULT_LISTEN_ADDRESS = "0.0.0.0"


class SyncronizedDict(dict):
    def __init__(self, *args):
        super(SyncronizedDict, self).__init__(args)
        self.mutex = Lock()

    def __delitem__(self, key):
        with self.mutex:
            super(SyncronizedDict, self).__delitem__(key)

    def __setitem__(self, key, value):
        with self.mutex:
            super(SyncronizedDict, self).__setitem__(key, value)


class THUBHandler(socketserver.BaseRequestHandler):
    # Control messages
    HUB_OUTPUT_SOCKET_TYPE_CAPTURER = b"HOSTC"
    HUB_OUTPUT_SOCKET_TYPE_INJECTOR = b"HOSTI"
    HUB_INPUT_SOCKET_TYPE_CLIENT = b'HISTC'
    CLIENT_CONTROLL_SET_SOCKET_MAC_ADDRESS = b'CCSSM'

    def _read_full_packet_by_size(self, expected_packet_size):
        full_packet = b""
        while len(full_packet) < expected_packet_size:
            packet = self.request.recv(expected_packet_size - len(full_packet))
            if packet == b"":
                ConnectionResetError("The socket was closed while reading")
            full_packet += packet
        return full_packet

    def _read_hub_packet(self):
        expected_packet_size = self.request.recv(5)
        if expected_packet_size != b"":
            next_byte = 0
            while ((chr(expected_packet_size[0]) not in digits) and (next_byte != b"")):
                next_byte = self.request.recv(1)
                expected_packet_size = expected_packet_size[1:] + next_byte

            if b'\x00' in expected_packet_size:
                expected_packet_size = int(expected_packet_size[:expected_packet_size.index(b'\x00')].decode())
            else:
                expected_packet_size = int(expected_packet_size.decode())

            return self._read_full_packet_by_size(expected_packet_size)
        else:
            raise ConnectionResetError("The socket was closed while reading")

    def _read_client_packet(self):
        pack_size = self.request.recv(5)
        expected_packet_size = pack_size.split(b'\x00')[0]
        if expected_packet_size == self.CLIENT_CONTROLL_SET_SOCKET_MAC_ADDRESS:
            mac_address = self._read_full_packet_by_size(6)
            self.server.update_mac_address(self.client_mac, mac_address)
            self.client_mac = mac_address
        elif expected_packet_size != b"":
            next_byte = 0
            while ((chr(expected_packet_size[0]) not in digits) and (next_byte != b"")):
                next_byte = self.request.recv(1)
                expected_packet_size = expected_packet_size[1:] + next_byte

            if b'\x00' in expected_packet_size:
                expected_packet_size = int(expected_packet_size[:expected_packet_size.index(b'\x00')].decode())
            else:
                expected_packet_size = int(expected_packet_size.decode())

            packet = self._read_full_packet_by_size(expected_packet_size)
            if (self.server.hub_input_queue is not None):
                self.server.hub_input_queue.put(packet)
        else:
            raise ConnectionResetError("The socket was closed while reading")

    def _prepare_packet(self, packet_data):
        packetlen = str(len(packet_data))
        packetlen = packetlen.encode() + (b'\x00' * (5 - len(packetlen)))
        return packetlen + packet_data

    def _handle_client(self):
        print(f"New client connection from {self.client}!")
        self.client_mac = self.server.get_random_mac_address()
        self.server.register_new_client(self.client_mac)
        while True:
            should_sleep = True
            readable_sockets, _, _ = select.select([self.request], [], [], 0)
            try:
                if (readable_sockets):
                    self._read_client_packet()
                    should_sleep = False
                if (not self.server.hub_output_listeners[self.client_mac].empty()):
                    packet = self._prepare_packet(self.server.hub_output_listeners[self.client_mac].get())
                    self.request.sendall(packet)
                    should_sleep = False
            except (ConnectionResetError, ConnectionError):
                self.request.close()
                print(f"Client socket {self.client} disconnected!")
                self.server.unregister_client(self.client_mac)
                return

            if should_sleep:
                sleep(SLEEP_TIME_SEC)

    def _handle_hub_capturer(self):
        print(f"New hub read connection from {self.client}!")
        while True:
            should_sleep = True
            read_ready, _, _ = select.select([self.request], [], [], 0)
            try:
                if read_ready:
                    self.server.send_packet_to_clients(self._read_hub_packet())
                    should_sleep = False
            except ConnectionResetError:
                self.request.close()
                print(f"Hub server capture socket {self.client} disconnected!")
                return

            if should_sleep:
                sleep(SLEEP_TIME_SEC)

    def _handle_hub_injector(self):
        print(f"New hub write connection from {self.client}!")
        self.server.register_hub_injector_queue()
        while True:
            should_sleep = True
            read_ready, _, _ = select.select([self.request],[],[],0)
            # This is a socket that no data is expected to be read from, so we use select to see if it was closed.
            if read_ready:
                self.request.close()
                print(f"Hub server injeciton socket {self.client} disconnected!")
                self.server.unregister_hub_injector_queue()
                return
            if (not self.server.hub_input_queue.empty()):
                packet = self._prepare_packet(self.server.hub_input_queue.get())
                try:
                    self.request.sendall(packet)
                    should_sleep = False
                except ConnectionError:
                    self.request.close()
                    print(f"Hub server injeciton socket {self.client} disconnected!")
                    self.server.unregister_hub_injector_queue()
                    return

            if should_sleep:
                sleep(SLEEP_TIME_SEC)

    def handle(self):
        self.header = self.request.recv(5)
        self.client = self.request.getpeername()

        if self.header == self.HUB_OUTPUT_SOCKET_TYPE_INJECTOR:
            self._handle_hub_injector()
        elif self.header == self.HUB_OUTPUT_SOCKET_TYPE_CAPTURER:
            self._handle_hub_capturer()
        elif self.header == self.HUB_INPUT_SOCKET_TYPE_CLIENT:
            self._handle_client()
        else:
            self.request.close()


class THUBServer(socketserver.ThreadingTCPServer):
    def __init__(self, listen_address, listen_handler, certfile, keyfile):
        super(socketserver.ThreadingTCPServer, self).__init__(listen_address, listen_handler)
        self.certfile = certfile
        self.keyfile = keyfile
        self.hub_input_queue_mutex = Lock()
        self.hub_input_queue = None
        self.hub_output_listeners = SyncronizedDict()

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile = self.certfile,
                                 keyfile = self.keyfile,
                                 ssl_version = ssl.PROTOCOL_SSLv23)
        return connstream, fromaddr

    def register_hub_injector_queue(self):
        self.hub_input_queue = queue.Queue()

    def unregister_hub_injector_queue(self):
        self.hub_input_queue = None

    def register_new_client(self, client_mac):
        self.hub_output_listeners[client_mac] = queue.Queue()

    def unregister_client(self, client_mac):
        self.hub_output_listeners.pop(client_mac)

    def update_mac_address(self, source_mac_address, dest_mac_address):
        packet_queue = self.hub_output_listeners[source_mac_address]
        self.unregister_client(source_mac_address)
        self.hub_output_listeners[dest_mac_address] = packet_queue

    def send_packet_to_clients(self, packet):
        # Assuming the packet is ethernet packet
        packet_source_mac = packet[6:12]
        for client_mac in self.hub_output_listeners.keys():
            if client_mac != packet_source_mac:
                self.hub_output_listeners[client_mac].put(packet)

    def get_random_mac_address(self):
        address = THUBServer._random_mac()
        while address in self.hub_output_listeners.keys():
            address = THUBServer._random_mac()
        return address

    @staticmethod
    def _random_mac():
        return bytes([random.randint(0,255) for i in range(MAC_ADDRESS_LENGTH)])


def parse_argumets():
    parser = argparse.ArgumentParser(description='THUB server')
    parser.add_argument('--bind', '-b', help=f"The IP address the server will listen on. Defaults to {DEFAULT_LISTEN_ADDRESS}",
        type=str, required=False, default=DEFAULT_LISTEN_ADDRESS)
    parser.add_argument('--port', '-p', help=f"The port the server will listen on",
        type=int, required=True)
    parser.add_argument('--cert', '-c', help=f"The path to the certificate file. Defaults to {DEFAULT_SERVER_CERT}",
        type=str, required=False, default=DEFAULT_SERVER_KEY)
    parser.add_argument('--key', '-k', help=f"The path to the keyfile. Defaults to {DEFAULT_SERVER_KEY}",
        type=str, required=False, default=DEFAULT_SERVER_KEY)
    return parser.parse_args()


def main():
    args = parse_argumets()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    if path.isfile(args.cert) and path.isfile(args.key):
        with THUBServer((args.bind, args.port), THUBHandler, args.cert, args.key) as server:
            server.serve_forever()
    else:
        print(f"Could not find the key file '{args.key}' or the certificate '{args.cert}'")


if __name__ == '__main__':
    main()
