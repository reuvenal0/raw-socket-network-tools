# Raw Socket Network Tools

A collection of low-level networking tools implemented in C using raw sockets.

The project includes custom implementations of:

- ICMP Ping
- Traceroute
- TCP SYN Port Scanner

The goal of the project is to work directly with IPv4, ICMP, and TCP packets, including manual packet construction, checksum calculation, TTL handling, RTT measurement, and response validation.

## Features

### ICMP Ping

A custom implementation of the `ping` utility using ICMP Echo Request and Echo Reply packets.

Features include:

- Raw ICMP sockets
- Manual ICMP packet construction
- ICMP checksum calculation
- Sequence number and identifier validation
- Round-trip time measurement
- TTL extraction from received IPv4 packets
- Packet loss statistics
- Minimum, average, and maximum RTT statistics
- Configurable packet count
- Flood mode
- Graceful termination using `Ctrl+C`

### Traceroute

A traceroute-style utility that discovers the route to a destination by sending ICMP Echo Request packets with increasing TTL values.

Features include:

- Manual IPv4 and ICMP packet construction
- Incremental TTL values
- ICMP Time Exceeded handling
- ICMP Echo Reply detection
- Three probes per hop
- RTT measurement for each probe
- Response validation using ICMP identifiers
- Maximum hop limit
- Timeout handling with `*` output

### TCP SYN Port Scanner

A TCP port scanner that scans ports using manually constructed TCP SYN packets.

Features include:

- IPv4 and TCP packet construction
- TCP SYN scanning
- TCP pseudo-header checksum calculation
- SYN+ACK detection for open ports
- RST detection for closed ports
- DNS hostname resolution
- Automatic local IPv4 address detection
- Scanning of TCP ports 1-65535
- RST-based connection cleanup

## Requirements

- Linux
- GCC
- GNU Make
- Root privileges for raw sockets

The project was developed and tested on Ubuntu 22.04.

## Build

Build all programs:

```bash
make
````

Build a specific program:

```bash
make ping
make traceroute
make port_scanning
```

Remove generated binaries:

```bash
make clean
```

## Usage

Raw sockets require elevated privileges, so the programs should be executed with `sudo`.

### Ping

```bash
sudo ./ping -a <destination_ip>
```

Send a specific number of packets:

```bash
sudo ./ping -a <destination_ip> -c 10
```

Flood mode:

```bash
sudo ./ping -a <destination_ip> -f
```

### Traceroute

```bash
sudo ./traceroute -a <destination_ip>
```

### Port Scanner

```bash
sudo ./port_scanning -a <host>
```

The target can be either an IPv4 address or a hostname.

## Technical Details

The project works directly with network protocol headers rather than relying only on high-level socket abstractions.

Key concepts demonstrated include:

* Raw sockets
* IPv4 packet headers
* ICMP Echo Request and Echo Reply
* ICMP Time Exceeded messages
* TCP SYN scanning
* Internet checksum calculation
* TCP pseudo headers
* TTL-based route discovery
* Packet parsing and validation
* `poll()`-based timeout handling
* `CLOCK_MONOTONIC` timing
* POSIX signal handling
* DNS resolution with `getaddrinfo()`

## Ping Statistics

The Ping implementation collects and displays:

* Packets transmitted
* Packets received
* Packet loss percentage
* Total execution time
* Minimum RTT
* Average RTT
* Maximum RTT

## Traceroute Behavior

The traceroute implementation sends three probes for each TTL value.

Intermediate routers may not always respond with ICMP Time Exceeded messages. In these cases, the program prints `*`, similar to standard traceroute utilities.

The trace stops when:

* An ICMP Echo Reply is received from the destination, or
* The maximum number of hops is reached.

## Port Scanner Behavior

The scanner sends a TCP SYN packet to each destination port.

Responses are interpreted as follows:

* `SYN + ACK` → port is considered open
* `RST` → port is considered closed
* No response before timeout → port is treated as closed/unresponsive

When an open port responds with `SYN + ACK`, the scanner sends an appropriate RST packet to terminate the half-open connection.

## Limitations

* The port scanner currently supports TCP only.
* Raw sockets require root privileges or equivalent Linux capabilities.
* Traceroute results may vary because some routers block or ignore ICMP messages.
* Network firewalls and filtering rules may affect scan results.
* The current implementation uses IPv4 only.

## Project Structure

```text
.
├── ping.c
├── traceroute.c
├── port_scanning.c
├── Makefile
└── README.md
```

## Educational Context

This project was originally developed as part of a Computer Networks course and demonstrates practical implementation of low-level network protocols and packet processing in C.

## Disclaimer

The port scanning functionality is intended for educational purposes.

Only scan systems and networks that you own or have explicit permission to test.
