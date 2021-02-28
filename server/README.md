# Thub Server

**Tunneled Hub** - A tool for pivoting in a target's network with multiple attackers.

## Server - Details
### Usage
In order to run the server, use pre-generated SSL key pair, or simply generate one using:
```bash
./genkey.sh
```
Once you have an SSL key pair, just run:
```bash
./server -p PORT [-c CRT_FILE] [-k KEY_FILE]
```
You can also specify `-b` to specify the address to bind on.
