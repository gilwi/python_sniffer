#!/usr/bin/python3

import argparse
import socket
import sys
import time
import multiprocessing
from struct import pack, unpack


class L2Data:
    def __init__(self, data):
        # Retrieve ethernet header data for easier slicing
        # data is a memoryview
        self.__eth_header = data

        # Retrieve formatted string corresponding to
        # ethernet header information
        self.dst_mac = fmt_macaddr(self.__eth_header[:6].hex())
        self.src_mac = fmt_macaddr(self.__eth_header[6:12].hex())
        self.eth_type = self.__eth_header[12:14].hex()

    def __repr__(self):
        return "DST_MAC: {}\nSRC_MAC: {}\nETH_TYPE: {}".format(
            self.dst_mac, self.src_mac, self.eth_type
        )


class IPData:

    def __init__(self, data):

        # Retrieve ethernet encapsulation data
        # data is a memoryview
        self.__ip_header = data

        self.__info = bin(int(self.__ip_header[:2].hex(), 16))[2:].zfill(16)

        self.version = int("0b" + self.__info[:4], 2)
        if self.version == 4:

            self.ihl = int("0b" + self.__info[4:8], 2)
            self.tos_dcsp = self.__info[8:14]
            self.tos_ecn = self.__info[14:16]

            # Re-calculating fields with correct offsets for IPv4
            # Length is 16 bits starting at byte 2
            self.len = unpack("!H", self.__ip_header[2:4])[0]

            self.frag_id = unpack("!H", self.__ip_header[4:6])[0]
            flags_offset = unpack("!H", self.__ip_header[6:8])[0]
            self.flags = (flags_offset & 0xE000) >> 13
            self.frag_offset = flags_offset & 0x1FFF

            self.ttl = self.__ip_header[8]
            self.proto = self.__ip_header[9]
            self.hdr_cksum = self.__ip_header[10:12].hex()

            self.src_ip = socket.inet_ntoa(bytes(self.__ip_header[12:16]))
            self.dst_ip = socket.inet_ntoa(bytes(self.__ip_header[16:20]))

            self.options = None
            if self.ihl > 5:
                self.options = self.__ip_header[20 : self.ihl * 4].hex()
            self.payload = self.__ip_header[self.ihl * 4 :]
        elif self.version == 6:
            # IPv6 version is 4 bits, Traffic Class 8 bits, Flow Label 20 bits
            # Byte 0: [Version 4][Traffic Class 4]
            # Byte 1: [Traffic Class 4][Flow Label 4]
            # Byte 2-3: [Flow Label 16]
            self.traff_class = self.__ip_header[:2].hex()[1:3]
            self.flow_lbl = self.__ip_header[1:4].hex()[1:]

            self.payload_len = unpack("!H", self.__ip_header[4:6])[0]
            self.next_header = self.__ip_header[6]
            self.proto = self.next_header  # For compatibility with IPv4
            self.hop_limit = self.__ip_header[7]

            self.src_ip = fmt_ip6addr(self.__ip_header[8:24].hex())
            self.dst_ip = fmt_ip6addr(self.__ip_header[24:40].hex())
            self.payload = self.__ip_header[40:]

    def __repr__(self):
        if self.version == 4:
            return (
                "VERSION: {}\nINTERNET HDR LENGTH: {}\nTOS: {} {}\n"
                "LEN: {}\nFRAG_ID: {}\nFLAGS: {}\n"
                "FRAG_OFFSET: {}\nTTL: {}\nPROTO: {}\nHDR_CKSUM: {}"
                "\nSRC_IP: {}\nDST_IP: {}\nOPTIONS: {}\n".format(
                    self.version,
                    self.ihl,
                    self.tos_dcsp,
                    self.tos_ecn,
                    self.len,
                    self.frag_id,
                    self.flags,
                    self.frag_offset,
                    self.ttl,
                    self.proto,
                    self.hdr_cksum,
                    self.src_ip,
                    self.dst_ip,
                    self.options,
                )
            )
        if self.version == 6:
            return (
                "VERSION: {}\nTRAFFIC_CLASS: {}\nPAYLOAD_LEN: {}\nNEXT_HEADER: {}\n"
                "HOP_LIMIT: {}\nSRC_IP: {}\nDST_IP: {}\n".format(
                    self.version,
                    self.traff_class,
                    self.payload_len,
                    self.next_header,
                    self.hop_limit,
                    self.src_ip,
                    self.dst_ip,
                )
            )


class TCPData:
    def __init__(self, data):
        self.__tcp_header = data
        # TCP header is at least 20 bytes
        self.src_port, self.dst_port, self.seq, self.ack, self.offset_reserved_flags = (
            unpack("!HHLLH", self.__tcp_header[:14])
        )
        self.offset = (self.offset_reserved_flags >> 12) * 4
        self.flags = self.offset_reserved_flags & 0x1FF  # 9 bits of flags

        self.window = unpack("!H", self.__tcp_header[14:16])[0]
        self.checksum = self.__tcp_header[16:18].hex()
        self.urgent_ptr = unpack("!H", self.__tcp_header[18:20])[0]

        # Flags extraction
        self.flag_ns = (self.flags & 0x100) >> 8
        self.flag_cwr = (self.flags & 0x80) >> 7
        self.flag_ece = (self.flags & 0x40) >> 6
        self.flag_urg = (self.flags & 0x20) >> 5
        self.flag_ack = (self.flags & 0x10) >> 4
        self.flag_psh = (self.flags & 0x08) >> 3
        self.flag_rst = (self.flags & 0x04) >> 2
        self.flag_syn = (self.flags & 0x02) >> 1
        self.flag_fin = self.flags & 0x01

        self.options = None
        if self.offset > 20:
            self.options = self.__tcp_header[20 : self.offset].hex()

        self.payload = self.__tcp_header[self.offset :]

    def __repr__(self):
        flags_str = "[NS: {}, CWR: {}, ECE: {}, URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}]".format(
            self.flag_ns,
            self.flag_cwr,
            self.flag_ece,
            self.flag_urg,
            self.flag_ack,
            self.flag_psh,
            self.flag_rst,
            self.flag_syn,
            self.flag_fin,
        )
        return (
            "TCP: SRC_PORT: {}, DST_PORT: {}, SEQ: {}, ACK: {}\n"
            "OFFSET: {}, FLAGS: {}\n"
            "WINDOW: {}, CHECKSUM: {}, URGENT_PTR: {}\n"
            "OPTIONS: {}".format(
                self.src_port,
                self.dst_port,
                self.seq,
                self.ack,
                self.offset,
                flags_str,
                self.window,
                self.checksum,
                self.urgent_ptr,
                self.options,
            )
        )


class UDPData:
    def __init__(self, data):
        self.__udp_header = data
        self.src_port, self.dst_port, self.length, self.checksum = unpack(
            "!HHHH", self.__udp_header[:8]
        )
        self.payload = self.__udp_header[8:]

    def __repr__(self):
        return "UDP: SRC_PORT: {}, DST_PORT: {}, LENGTH: {}, CHECKSUM: {:04x}".format(
            self.src_port, self.dst_port, self.length, self.checksum
        )


class ICMPData:
    def __init__(self, data):
        self.__icmp_header = data
        self.type, self.code, self.checksum = unpack("!BBH", self.__icmp_header[:4])
        self.payload = self.__icmp_header[4:]

        self.type_map = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
        }

    def __repr__(self):
        type_str = self.type_map.get(self.type, "Unknown Type")
        return "ICMP: TYPE: {} ({}), CODE: {}, CHECKSUM: {}".format(
            self.type, type_str, self.code, self.checksum
        )


class ArpData:

    def __init__(self, data):

        # Retrieve ethernet encapsulation data
        self.__arp_hdr = data

        # Slice ARP header into separate bytes objects
        self.hw_type = unpack("!H", self.__arp_hdr[:2])[0]
        self.proto_type = self.__arp_hdr[2:4].hex()
        self.hw_addr_len = self.__arp_hdr[4]
        self.proto_addr_len = self.__arp_hdr[5]
        self.ope = unpack("!H", self.__arp_hdr[6:8])[0]

        self.src_hw_addr = fmt_macaddr(self.__arp_hdr[8 : 8 + self.hw_addr_len].hex())

        # Source protocol address
        spa_start = 8 + self.hw_addr_len
        spa_end = spa_start + self.proto_addr_len
        self.src_proto_addr = ".".join(
            map(str, bytes(self.__arp_hdr[spa_start:spa_end]))
        )

        # Destination hardware address
        tha_start = spa_end
        tha_end = tha_start + self.hw_addr_len
        self.dst_hw_addr = fmt_macaddr(self.__arp_hdr[tha_start:tha_end].hex())

        # Destination protocol address
        tpa_start = tha_end
        tpa_end = tpa_start + self.proto_addr_len
        self.dst_proto_addr = ".".join(
            map(str, bytes(self.__arp_hdr[tpa_start:tpa_end]))
        )

    def __repr__(self):
        return (
            "HW_TYPE: {}\nPROTO_TYPE: {}\nHW_ADDR_LEN: {}\nPROTO_ADDR_LEN: {}\nOPE: {}\nSRC_HW_ADDR:"
            " {}\nSRC_PROTO_ADDR: {}\nDST_HW_ADDR: {}\nDST_PROTO_ADDR: {}".format(
                self.hw_type,
                self.proto_type,
                self.hw_addr_len,
                self.proto_addr_len,
                self.ope,
                self.src_hw_addr,
                self.src_proto_addr,
                self.dst_hw_addr,
                self.dst_proto_addr,
            )
        )


class PcapExporter:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, "wb")
        # Global Header: magic(I), v_maj(H), v_min(H), zone(i), sig(I), snap(I), net(I)
        # Using little-endian (<) as it's common
        global_header = pack("<IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.file.write(global_header)

    def write_packet(self, data):
        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1000000)
        incl_len = len(data)
        orig_len = len(data)
        # Packet Header: ts_sec(I), ts_usec(I), incl_len(I), orig_len(I)
        packet_header = pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        self.file.write(packet_header)
        self.file.write(data)
        self.file.flush()

    def close(self):
        self.file.close()


def fmt_macaddr(mac_addr):
    # Retrieve str hex form of received bytes
    t = iter(mac_addr)
    # Return Unix-like mac address in the form ff:ff:ff:ff:ff:ff
    return ":".join(a + b for a, b in zip(t, t))


def fmt_ip6addr(ip6_addr):
    # Retrieve hex form of mac address into iter
    t = iter(ip6_addr)
    # Return ipv6 str formatted like ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
    return ":".join(
        a + b + c + d if a + b + c + d != "0000" else ""
        for a, b, c, d in zip(t, t, t, t)
    )


def parse_args(args_in):
    parser = argparse.ArgumentParser(description="A simple python sniffer")
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Interactive mode to ask for options",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default="all",
        help="Interface name to sniff on (e.g., eth0, wlan0). Default: all",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of frames to capture (0 for infinite)",
    )
    parser.add_argument(
        "-p",
        "--proto",
        type=str,
        choices=["tcp", "udp", "icmp", "arp"],
        help="Filter by protocol",
    )
    parser.add_argument("--port", type=int, help="Filter by port (TCP/UDP)")
    parser.add_argument("-o", "--output", type=str, help="Output PCAP file path")
    return parser.parse_args(args_in)


def get_interface_interactively():
    interfaces = socket.if_nameindex()
    print("Available interfaces:")
    for idx, name in interfaces:
        print(f"  {idx}: {name}")

    while True:
        choice = input(
            f"Enter interface name or index to sniff on ({interfaces[0][1]}): "
        ).strip()

        # Default fallback if just hit Enter
        if not choice:
            return interfaces[0][1]

        # Check if it's an index or a generic name
        if choice.isdigit():
            idx = int(choice)
            matched = [name for i, name in interfaces if i == idx]
            if matched:
                return matched[0]
        else:
            matched = [name for i, name in interfaces if name == choice]
            if matched:
                return matched[0]

        print("Invalid interface. Please try again.")


def setup_socket(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    if interface:
        try:
            s.bind((interface, socket.htons(3)))
        except OSError as e:
            print(f"Error binding to interface '{interface}': {e}")
            sys.exit(1)
    return s


def matches_filter(data, proto_filter, port_filter):
    # data is a memoryview
    eth_header = L2Data(data[:14])
    eth_payload = data[14:]

    actual_proto = None
    ports = []

    if eth_header.eth_type in ["0800", "86dd"]:
        ip_req = IPData(eth_payload)
        if ip_req.proto == 6:
            actual_proto = "tcp"
            tcp_req = TCPData(ip_req.payload)
            ports = [tcp_req.src_port, tcp_req.dst_port]
        elif ip_req.proto == 17:
            actual_proto = "udp"
            udp_req = UDPData(ip_req.payload)
            ports = [udp_req.src_port, udp_req.dst_port]
        elif ip_req.proto == 1:
            actual_proto = "icmp"
    elif eth_header.eth_type == "0806":
        actual_proto = "arp"

    if proto_filter and actual_proto != proto_filter:
        return False
    if port_filter and port_filter not in ports:
        return False

    return True


def handle_frame(data, addr, frame_id):
    # data is a memoryview
    if_name = addr[0]
    eth_header = L2Data(data[:14])
    eth_payload = data[14:]

    print()
    print("-" * 100)
    print("Frame id: {} | Interface: {}".format(frame_id, if_name))
    print(repr(eth_header))

    if eth_header.eth_type in ["0800", "86dd"]:
        ip_req = IPData(eth_payload)
        print()
        print(repr(ip_req))

        if ip_req.proto == 6:
            tcp_req = TCPData(ip_req.payload)
            print(repr(tcp_req))
        elif ip_req.proto == 17:
            udp_req = UDPData(ip_req.payload)
            print(repr(udp_req))
        elif ip_req.proto == 1:
            icmp_req = ICMPData(ip_req.payload)
            print(repr(icmp_req))
    elif eth_header.eth_type == "0806":
        arp_req = ArpData(eth_payload)
        print()
        print(repr(arp_req))


def capture_worker(interface, queue, stop_event):
    s = setup_socket(interface)
    print(f"Sniffing on {'all interfaces' if not interface else interface}...")

    try:
        while not stop_event.is_set():
            # Use a timeout if possible, but raw sockets might block
            # For now, we'll let it block or use a small timeout if we had it
            message, addr = s.recvfrom(65535)
            # Add to queue as (bytes, addr)
            queue.put((message, addr))
    except Exception as e:
        if not stop_event.is_set():
            print(f"Capture error: {e}")
    finally:
        s.close()


def parser_worker(args, queue, stop_event):
    frameCount = 0
    matchedCount = 0
    pcap_exporter = None

    if args.output:
        pcap_exporter = PcapExporter(args.output)
        print(f"Exporting to {args.output}...")

    try:
        while not stop_event.is_set() or not queue.empty():
            try:
                # Use a timeout to avoid blocking forever if stop_event is set
                packet_info = queue.get(timeout=0.1)
                message, addr = packet_info

                # Zero-copy optimization: use memoryview
                data = memoryview(message)

                if matches_filter(data, args.proto, args.port):
                    handle_frame(data, addr, frameCount)
                    if pcap_exporter:
                        pcap_exporter.write_packet(message)
                    matchedCount += 1

                frameCount += 1

                if args.count != 0 and matchedCount >= args.count:
                    print(f"\nCaptured {args.count} matching frames. Exiting.")
                    stop_event.set()
                    break

            except multiprocessing.queues.Empty:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        if pcap_exporter:
            pcap_exporter.close()


def main():
    args = parse_args(sys.argv[1:])
    interface = args.interface

    if args.interactive:
        interface = get_interface_interactively()

    if interface == "all":
        interface = ""

    queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()

    capture_proc = multiprocessing.Process(
        target=capture_worker, args=(interface, queue, stop_event)
    )
    parser_proc = multiprocessing.Process(
        target=parser_worker, args=(args, queue, stop_event)
    )

    capture_proc.start()
    parser_proc.start()

    try:
        while parser_proc.is_alive():
            parser_proc.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        stop_event.set()
    finally:
        # Give some time for workers to clean up
        capture_proc.terminate()
        capture_proc.join()
        parser_proc.join()
        sys.exit(0)


if __name__ == "__main__":
    main()
