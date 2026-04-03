# Python Sniffer

A low-level network sniffer implemented in Python 3 using raw sockets. This project is designed for educational purposes to understand packet structure and protocol parsing.

## Key Features

- **Raw Socket Capture:** Captures Ethernet frames directly.
- **Protocol Parsing:** Supports Ethernet (Layer 2), IPv4/IPv6, ARP (Layer 3), and TCP/UDP/ICMP (Layer 4).
- **Multi-Interface Support:** Can sniff on a specific interface or all available ones.
- **Frame Limit:** Optional limit on the number of captured packets.
- **Automated Testing:** Comprehensive test suite with mocked packets.

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
| `-c, --count <n>` | Stop after capturing `n` frames (default: 0 for infinite). |

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
