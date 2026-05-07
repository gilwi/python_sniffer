# Python Sniffer

A low-level network sniffer implemented in Python 3 using raw sockets. This project is designed for educational purposes to understand packet structure and protocol parsing.

## Key Features

- **Raw Socket Capture:** Captures Ethernet frames directly.
- **Protocol Parsing:** Supports Ethernet (Layer 2), IPv4/IPv6, ARP (Layer 3), and TCP/UDP/ICMP (Layer 4) with detailed flag and option parsing.
- **PCAP Persistence:** Export captured traffic to standard `.pcap` files for analysis in tools like Wireshark.
- **Advanced Filtering:** Filter by protocol and port via CLI arguments.

## Getting started

### Requirements

- A Linux host (for raw socket support)
- Python 3.9+
- Administrative privileges (`sudo`)

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --interactive` | Interactively choose a network interface. |
| `--interface <name>` | Specify interface (e.g., `eth0`, `lo`). Use `all` for all interfaces. |
| `-c, --count <n>` | Stop after capturing `n` matching frames (default: 0 for infinite). |
| `-p, --proto <p>` | Filter by protocol (`tcp`, `udp`, `icmp`, `arp`). |
| `--port <n>` | Filter by TCP/UDP port. |
| `-o, --output <path>` | Save captured packets to a PCAP file. |

---

## Usage Examples

### Capture and Filter
Capture only 50 TCP packets on `eth0`:
```bash
sudo python3 sniffer/sniffer.py --interface eth0 --proto tcp --count 50
```

### Persistence
Save all UDP traffic to a file:
```bash
sudo python3 sniffer/sniffer.py --proto udp --output capture.pcap
```

### Filtering by Port
Capture traffic on port 80 (HTTP):
```bash
sudo python3 sniffer/sniffer.py --port 80
```

---

## Execution Methods

### Docker (Recommended)

Run with a single command (defaults to all interfaces):
```bash
docker compose up --build
```

To run with specific options (e.g., capture 10 frames):
```bash
docker compose run --rm sniffer --count 10
```

### Vagrant

Start the VM and run the sniffer in one command:
```bash
vagrant up && vagrant ssh -c 'sudo python3 /app/sniffer/sniffer.py --interface all'
```

Alternatively, join the VM:
```bash
vagrant ssh
run-sniffer
```

### Local (Manual)

```bash
sudo python3 sniffer/sniffer.py --interface all
```

---

## Testing

Automated tests are performed using `pytest` with mocked packet data.

### Run Tests via Docker
```bash
docker compose build sniffer
docker compose run --rm --entrypoint pytest sniffer tests/test_sniffer.py
```

### Run Tests Locally
```bash
pip install pytest
pytest tests/test_sniffer.py
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for future development plans and upcoming features.
