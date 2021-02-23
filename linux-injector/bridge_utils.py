import fcntl
import socket
import struct


SIOCBRADDBR     = 0x89a0
SIOCBRDELBR     = 0x89a1
SIOCBRADDIF     = 0x89a2
SIOCBRDELIF     = 0x89a3
SIOCGIFINDEX    = 0x8933


def add_bridge(name):
    s = socket.socket()
    try:
        fcntl.ioctl(s.fileno(), SIOCBRADDBR, name)
    finally:
        s.close()


def delete_bridge(name):
    s = socket.socket()
    try:
        fcntl.ioctl(s.fileno(), SIOCBRDELBR, name)
    finally:
        s.close()


def add_interface(bridge_name, iface_name):
    devindex = get_inteface_index(iface_name)
    ifreq = struct.pack('16si', bridge_name, devindex)
    s = socket.socket()
    try:
        fcntl.ioctl(s.fileno(), SIOCBRADDIF, ifreq)
    finally:
        s.close()


def del_inerface(bridge_name, iface_name):
    devindex = get_inteface_index(iface_name)
    ifreq = struct.pack('16si', bridge_name, devindex)
    s = socket.socket()
    try:
        fcntl.ioctl(s.fileno(), SIOCBRDELIF, ifreq)    
    finally:
        s.close()


def get_inteface_index(device_name):
    index = -1
    s = socket.socket()
    ifreq = struct.pack('16si', device_name, 0)
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        index = struct.unpack("16si", res)[1]
    finally:
        s.close()
    return index
