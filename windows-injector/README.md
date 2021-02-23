# Thub Windows Injector

**Tunneled Hub** - A tool for pivoting in a target's network with multiple attackers.

## Thub Windows Injector - Details
### Usage
In order to execute thub_windows_injector, The user must determine what interface the program should execute on. In order to discover that, the user can simply execute:
```bash
thub_windows_injector.exe -d
```
and see a list of the interfaces that capturing can be done on.
Once the interface is determined, and there is a server executing the server, the user can simply run:
```bash
thub_windows_injector.exe -i INTERFACE_ID -s SERVER_IP -p SERVER_PORT
```

#### Compilation requiremets
* The compiling machine must have OpenSSL (developer pack) installed, and must have the WpdPack.
* In the given configuration OpenSSL is to be placed in `..\external_libs\openssl\openssl-32`/`..\external_libs\openssl\openssl-64` (Depending of course on the target compilation).
* In the given configuration WpdPack (WinPcap) is to be placed in `..\external_libs\WpdPack`.

### Notes
* Note that in order to execute properly thub_windows_injector, the Compromised Machine must have winpcap installed.
* Note that while using the client, there is no access to the actual physical device thub_windows_injector is running on, as the packets are injected on the line, and are not passed through the Compromised Machine network stack. Meaning the packets sent by attackers are not processed by the Compromised Machine, and only sent directly to the network.
* While capturing the network, a BPF filter is applied, to avoid capturing the thub communication with the server - The filtering is done by the server IP address. Meaning no traffic to the same IP address will be captured and visible on the generated TAP devices.
