# Project Roadmap: Python Sniffer

This roadmap outlines the planned evolution of the Python Sniffer project, moving from a basic educational tool to a more robust protocol analyzer.

## Phase 1: Core Protocol Expansion (Short Term)
*Goal: Support the most common transport and control protocols.*

- [ ] **Transport Layer Parsing:**
    - [ ] Implement `TCPData` class (Flags, Ports, Sequence numbers).
    - [ ] Implement `UDPData` class (Ports, Length, Checksum).
- [ ] **ICMP Support:**
    - [ ] Parse ICMP types and codes (Echo Request/Reply, Destination Unreachable).
- [ ] **Persistence:**
    - [ ] Add PCAP (Packet Capture) file export support using `struct` to write standard header formats.
- [ ] **Filtering:**
    - [ ] Implement basic BPF-like filtering via command line (e.g., `--proto tcp`, `--port 80`).

## Phase 2: Technical Robustness & Performance (Mid Term)
*Goal: Improve reliability and handling of high-traffic scenarios.*

- [ ] **Error Handling:**
    - [ ] Robust handling of malformed packets and truncated frames.
    - [ ] Add logging instead of direct `print` statements for better debugging.
- [ ] **Performance:**
    - [ ] Implement a producer-consumer pattern using `multiprocessing` or `threading` to separate packet capture from parsing/display.
    - [ ] Zero-copy optimizations for byte slicing.
- [ ] **Test Suite:**
    - [ ] Create a comprehensive unit test suite using mock packet data.
    - [ ] Integration tests using `scapy` or `ping` to generate known traffic.

## Phase 3: User Experience & Visualization (Long Term)
*Goal: Make the tool more accessible and informative.*

- [ ] **Interactive TUI:**
    - [ ] Develop a Terminal User Interface (e.g., using `curses` or `textual`) for real-time packet browsing.
- [ ] **Traffic Statistics:**
    - [ ] Live dashboard showing bandwidth usage, protocol distribution, and top talkers.
- [ ] **DNS/HTTP Inspection:**
    - [ ] Basic application layer dissection (extracting DNS queries, HTTP Host headers).
- [ ] **Geolocation:**
    - [ ] Integrate IP geolocation to show where traffic is coming from.

## Phase 4: Security & Analysis (Advanced)
*Goal: Provide insights beyond simple packet headers.*

- [ ] **Anomaly Detection:**
    - [ ] Flag potential port scans or ARP spoofing attempts.
    - [ ] Detect unusual traffic patterns.
- [ ] **Session Tracking:**
    - [ ] Reassemble TCP streams to view complete conversations.

---
*Note: This is a living document and will be updated as the project evolves.*
