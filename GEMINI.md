# Gemini Context: Python Sniffer

This project is a low-level network sniffer implemented in Python 3, focusing on raw socket communication and manual packet parsing for educational purposes.

## Project Overview

- **Type:** Network Sniffer / Protocol Analyzer
- **Language:** Python 3 (requires `python3`)
- **Core Logic:** `sniffer/sniffer.py`
- **Dependencies:** Standard library only (`socket`, `struct`, `argparse`).

## Key Features

- **Raw Socket Capture:** Uses `socket.AF_PACKET`, `socket.SOCK_RAW`, and `socket.htons(3)` to capture all Ethernet frames.
- **Layer 2 Parsing:** Decodes Ethernet headers (Source MAC, Destination MAC, EtherType).
- **Layer 3 Parsing:** 
    - **IPv4:** Version, IHL, TOS, Fragment info, TTL, Protocol, Header Checksum, IPs, Options.
    - **IPv6:** Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, IPs.
    - **ARP:** Hardware/Protocol types, addresses, and operation codes.
- **Interactive Mode:** Supports selecting network interfaces interactively or via command-line arguments.

## Execution Requirements

- **Permissions:** Must be run with administrative privileges (e.g., `sudo`) to open raw sockets.
- **Interface:** Requires a valid network interface name (e.g., `eth0`, `wlan0`, `lo`).

## Directory Structure

- `sniffer/`: Contains the main sniffer implementation.
    - `sniffer.py`: The entry point for the sniffer.
- `tests/`: Contains basic raw socket capture tests.
    - `test.py`: Simple capture script (hardcoded to `eth0`).
    - `comp.py`: Similar to `test.py`, used for comparison or basic verification.
- `Vagrantfile`: Provided for setting up a consistent Linux environment for testing.

## Engineering Standards

- **Modular Parsing:** Protocol parsing is encapsulated in classes (`L2Data`, `IPData`, `ArpData`).
- **Binary Slicing:** Manual slicing of byte strings is used for header extraction.
- **Formatting:** Custom helper functions (`fmt_macaddr`, `fmt_ip6addr`) for human-readable output.

## Guidelines for Future Interactions

- When adding support for new protocols, create a dedicated data class and update the dispatch logic in `main()`.
- Ensure new parsing logic handles potential malformed packets or unexpected lengths gracefully.
- Test scripts in `tests/` should be updated to accept an interface argument instead of being hardcoded.
