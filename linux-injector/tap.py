import os
import socket
import select
import tap_utils as _tap_utils

from tap_exceptions import *


ETH_P_ALL = 3
MAX_PACKET_SIZE = 2 ** 16 #65535


class Tap(object):
    def __init__(self, device_name=b'\x00', ip=None, netmask=None, mac_address=None):
        self.tap_name = Tap._validate_tap_name_input(device_name)
        self.ip = ip
        self.netmask = netmask
        self._tap_handle = None
        if type(mac_address) == str:
            self.mac_address = mac_address.encode()
        else:
            self.mac_address = mac_address

    @staticmethod
    def _validate_tap_name_input(device_name):
        if type(device_name) is str:
            device_name = device_name.encode()
        elif type(device_name) is not bytes:
            raise InvalidTapNameError("The device name must be str or bytes!")
        if _tap_utils.check_if_device_exists(device_name):
            raise TapExistsError("A device with that name already exists!")
        return device_name

    def create_tap(self):
        self.tap_name, self._tap_handle = _tap_utils.add_tap(self.tap_name)
        if self.mac_address:
            _tap_utils.set_mac(self.tap_name, self.mac_address, self._tap_handle.fileno())
        self.mac_address = _tap_utils.get_mac_address(self.tap_name)
        self.raise_interface()
        if self.ip:
            self.set_IP(self.ip)
            if self.netmask:
                self.set_netmask(self.netmask)

    def __enter__(self):
        self.create_tap()
        return self

    def destroy_tap(self):
        self.shutdown_interface()
        # Destroys the tap device
        if self._tap_handle:
            self._tap_handle.close()

    def __exit__(self, type=None, value=None, tb=None):
        self.destroy_tap()

    def set_IP(self, ip):
        _tap_utils.set_ip_addr(self.tap_name, ip)
        self.ip = ip

    def set_netmask(self, netmask):
        _tap_utils.set_netmask(self.tap_name, netmask)
        self.netmask = netmask

    def is_ready_to_read(self):
        read_ready, _, _ = select.select([self._tap_handle], [], [], 0)
        return len(read_ready) == 1

    def send_packet(self, packet):
        os.write(self._tap_handle.fileno(), packet)

    def read_packet(self, size=MAX_PACKET_SIZE):
        packet = os.read(self._tap_handle.fileno(), size)
        return packet, packet[6:12]

    def raise_interface(self):
        _tap_utils.iff_up(self.tap_name)

    def shutdown_interface(self):
        _tap_utils.iff_down(self.tap_name)

    def _check_if_mac_has_changed(self):
        """
        Returns wether the mac address has been changed (via a different program)
        In case the mac address has indeed changed - updates the value of 'mac_address'
        """
        current_mac = _tap_utils.get_mac_address(self.tap_name)
        if self.mac_address != current_mac:
            self.mac_address = current_mac
            return True
        return False

    def __repr__(self):
        return f"Tap device {self.tap_name.decode()}"
