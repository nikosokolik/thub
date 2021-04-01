# THUB - Tunneled Hub `(Or The Hacker's Ultimate Buddy)`
**A tool for pivoting inside a target's network with multiple attackers.**

##### Motivaion
Thub is a tool that is designed to allow multiple attackers to inspect, research, and execute attacks on a compromised network, without interfering in each other's attacks. Using a single access point to a network, the attackers can execute [windows_injector](windows-injector) or [linux_injector](linux-injector) on a compromised machine, and the [client](client) on their attack Linux.
The client will then create a virtual TAP device on the executing Linux machine, that will allow the attacker to access the network directly as if the TAP is connected replacing the compromised machine's TAP device.
Using the same server additional attackers can also connect and execute additional attacks originating from the same access point.

##### Flow
1. The attackers set up a server containing the [server](server) directory.
2. The attackers execute [windows_injector](windows-injector) or [linux_injector](linux-injector) on a compromised machine. The program connects to the server and begins to forward traffic from the machine to the server and vice versa.
3. The attackers execute the [client](client) on their Linux devices, and begin exploring the compromised network.

## Disclaimers
* The code in this project and all it's subfolders is only for educational purposes. I am not responsible in any way for any malicious or illegal use of this code. Please make use of this code only with the permission of the target.
* This tool is designed for advanced pivoting and not for security, thereofre, I did not implement certificate validation in any of the client sides. The SSL Layer is there only to assure that the information is not sent unencrypted over the Internet.
