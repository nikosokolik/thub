# Thub - Tunneled Hub
**A tool for pivoting in a target's network with multiple attackers.**

##### Motivaion
Thub is a tool that is designed to allow multiple attackers to inspect, research, and execute attacks on a compromised network, without interfering in each other's attacks. Using a single access point to a network, the attackers can execute _windows_injector_ or _linux_injector_ on a compromised machine, and the _client_ on their attack Linux.
The client will then create a virtual TAP device on the executing Linux machine, that will allow the attacker to access the network directly as if the TAP is connected replacing the compromised machine's TAP device.
Using the same server additional attackers can also connect and execute additional attacks originating from the same access point.

##### Flow
1. The attackers set up a server containing the _server_ directory.
2. The attackers execute _windows_injector_ or _linux_injector_ on a compromised machine. The program connects to the server and begins to forward traffic from the machine to the server and vice versa.
3. The attackers execute the _client_ on their Linux devices, and begin exploring the compromised network.

## Disclaimer
* This code is only for educational purposes. I am not responsible in any way for any malicious or illegal use of this code. Please make use of this code only with the permission of the target.
