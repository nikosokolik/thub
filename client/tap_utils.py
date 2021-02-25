import os
import fcntl
import socket
import struct


AF_UNIX         = 0x1
IFF_UP          = 0x1
IFF_TAP         = 0x0002
IFF_NO_PI       = 0x1000
TUNSETIFF       = 0x400454ca
TUNSETOWNER     = 0x400454cc
SIOCSIFADDR     = 0x8916
SIOCSIFNETMASK  = 0x891c
SIOCSIFHWADDR   = 0x8924
SIOCGIFFLAGS    = 0x8913
SIOCSIFFLAGS    = 0x8914


def get_mac_address(device_name):
    s = socket.socket()
    try:
        ifreq = struct.pack('256s', device_name)
        mac_addr = fcntl.ioctl(s.fileno(), 0x8927, ifreq)[18:24]
    finally:
        s.close()
    return mac_addr


def check_if_device_exists(device_name):
    with open(r'/proc/net/dev', 'rb') as f:
        proc_net_dev_content = f.read()
    installed_devices = [i.split(b':')[0].strip() for i in proc_net_dev_content.splitlines()[2:]]
    return device_name in installed_devices


def add_tap(device_name):
    """
        Adds a tap device
        returns the human-readable name of the generated device and a handle to the device that must be kept for the
        garbage cleaner to not close the device.
    """
    tap = open('/dev/net/tun', 'r+b', buffering=0)
    ifr = struct.pack('16sH', device_name, IFF_TAP | IFF_NO_PI)
    created_device = fcntl.ioctl(tap, TUNSETIFF, ifr)
    fcntl.ioctl(tap, TUNSETOWNER, 1000)
    generated_device_name = created_device.split(b'\x00')[0]
    # The host program must keep a handle to tap at all times. Losing the handle closes the device.
    if not check_if_device_exists(generated_device_name):
        raise Exception('Could not add device!')
    return generated_device_name, tap


def set_mac(device_name, mac_address, device_fd):
    mac_bytes = [int(i, 16) for i in mac_address.split(b':')]
    ifreq = struct.pack('16sH6B8x', device_name, AF_UNIX, *mac_bytes)
    fcntl.ioctl(device_fd, SIOCSIFHWADDR, ifreq)


def set_ip_addr(device_name, ip):
    s = socket.socket()
    try:
        bin_ip = socket.inet_aton(ip)
        ifreq = struct.pack('16sH2s4s8s', device_name, socket.AF_INET, b'\x00' * 2, bin_ip, b'\x00' * 8)
        fcntl.ioctl(s.fileno(), SIOCSIFADDR, ifreq)
    finally:
        s.close()


def set_netmask(device_name, netmask):
    s = socket.socket()
    try:
        bin_ip = socket.inet_aton(netmask)
        ifreq = struct.pack('16sH2s4s8s', device_name, socket.AF_INET, b'\x00' * 2, bin_ip, b'\x00' * 8)
        fcntl.ioctl(s.fileno(), SIOCSIFNETMASK, ifreq)
    finally:
        s.close()


def iff_up(device_name):
    s = socket.socket()
    try:
        original_flags_ifreq = struct.pack("18s", device_name)
        request_result = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, original_flags_ifreq)
        flags = struct.unpack("16sh",request_result)[1]
        # Set the IFF_UP bit to be true
        if (flags & IFF_UP == 0x0):
            ifreq = struct.pack("16sh", device_name, flags + IFF_UP)
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifreq)
    finally:
        s.close()


def iff_down(device_name):
    s = socket.socket()
    try:
        original_flags_ifreq = struct.pack("18s", device_name)
        request_result = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, original_flags_ifreq)
        flags = struct.unpack("16sh",request_result)[1]
        # Set the IFF_UP bit to be false
        if (flags & IFF_UP == 0x1):
            ifreq = struct.pack("16sh", device_name, flags - IFF_UP)
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifreq)
    finally:
        s.close()
