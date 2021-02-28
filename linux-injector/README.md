# Thub Linux Injector

**Tunneled Hub** - A tool for pivoting in a target's network with multiple attackers.

## Thub Linux Injector - Details
## Overview
In general, the Linux injector, unlike the windows one, is written in python and simply reuses the [client](../client)'s code. The differences are in the introduction to the server (i.e. the server knows this is the injection point and not another client), and that in addition to creating a tap device the injector creates a "bridge" between the tap and the interface. This way by reading and writing to the tap, the OS is actually writing to the physical device.

### Usage
In order to execute the Linux injector, first, create a configuration file. You may copy `default_config.json`, or copy it from here:
```json
{
    "server": {
        "host": "127.0.0.1",
        "port": 12345
    },
    "tap": {
        "tap_name": null,
        "mac_address": null,
        "ip_address": null,
        "ip_netmask": null
    },
    "bridge": {
        "bridge_name": null,
        "physical_interface_name": "eth0"
    }
}

```
Be sure to change the host IP and port. In addition, you may preset the name of the tap device, the name of the bridge, MAC address, IP and Netmask.
Here is an example:
```json
{
    "server": {
        "host": "127.0.0.1",
        "port": 12345
    },
    "tap": {
        "tap_name": "taptap",
        "mac_address": "66:55:44:33:22:11",
        "ip_address": "192.168.1.150",
        "ip_netmask": "255.255.255.0"
    },
    "bridge": {
        "bridge_name": "br0",
        "physical_interface_name": "ens33"
    }
}
```
* Note that some MAC addresses are illegal, and the OS will not allow their use.
* Also, since the tap is only used to allow the device to capture and inject to another interface, the IP address and the MAC address have no real meaning, and therefore adding this information is redundant.

Once you have your configuration file ready, just execute:
```bash
./client -c CONFIGURATION_FILE
```

### Notes
* Note that the project is written in python3 and uses `f-strings`. Make sure to have python3.6 or above.
* Note that in order to create a TAP device, `CAP_NET_ADMIN` permission capability is required. Root user has this permission capability, or you can assign it to a user.
