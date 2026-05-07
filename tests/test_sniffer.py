import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Add the project root to sys.path to import the sniffer module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sniffer.sniffer import (
    parse_args,
    handle_frame,
    L2Data,
    IPData,
    ArpData,
    TCPData,
    UDPData,
    ICMPData,
    matches_filter,
    PcapExporter,
)


def test_matches_filter():
    udp_packet = bytes.fromhex(UDP_PACKET_HEX)
    arp_packet = bytes.fromhex(ARP_PACKET_HEX)

    # Proto filter
    assert matches_filter(udp_packet, "udp", None) is True
    assert matches_filter(udp_packet, "tcp", None) is False
    assert matches_filter(arp_packet, "arp", None) is True
    assert matches_filter(arp_packet, "udp", None) is False

    # Port filter (UDP 4660 / 22136)
    assert matches_filter(udp_packet, None, 4660) is True
    assert matches_filter(udp_packet, None, 22136) is True
    assert matches_filter(udp_packet, None, 80) is False

    # Combined filter
    assert matches_filter(udp_packet, "udp", 4660) is True
    assert matches_filter(udp_packet, "udp", 80) is False


def test_pcap_exporter(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    exporter = PcapExporter(str(pcap_file))
    packet = bytes.fromhex(UDP_PACKET_HEX)
    exporter.write_packet(packet)
    exporter.close()

    assert pcap_file.exists()
    with open(pcap_file, "rb") as f:
        header = f.read(24)
        assert len(header) == 24
        # Magic number 0xA1B2C3D4 in little-endian
        assert header[:4] == b"\xd4\xc3\xb2\xa1"

        packet_header = f.read(16)
        assert len(packet_header) == 16
        # incl_len and orig_len should be 47 (0x2f)
        assert packet_header[8:12] == b"\x2f\x00\x00\x00"
        assert packet_header[12:16] == b"\x2f\x00\x00\x00"

        packet_data = f.read()
        assert packet_data == packet


def test_parse_args_defaults():
    args = parse_args([])
    assert args.count == 0
    assert args.interface == "all"
    assert args.interactive is False


@pytest.mark.parametrize(
    "args_list, expected_count, expected_interface",
    [
        (["--count", "10"], 10, "all"),
        (["--interface", "eth0"], 0, "eth0"),
        (["-c", "5", "--interface", "lo"], 5, "lo"),
    ],
)
def test_parse_args_values(args_list, expected_count, expected_interface):
    args = parse_args(args_list)
    assert args.count == expected_count
    assert args.interface == expected_interface


def test_parse_args_interactive():
    args = parse_args(["-i"])
    assert args.interactive is True


# Hex strings for various packet types
# Ethernet (14 bytes) + IPv4 (20 bytes) + UDP (8 bytes)
UDP_PACKET_HEX = (
    "ffffffffffff"  # Dest MAC
    "000000000000"  # Src MAC
    "0800"  # Type: IPv4
    "45000020"  # IP: Version 4, IHL 5, Total Len 32
    "00000000"  # IP: ID, Flags, Frag Offset
    "40110000"  # IP: TTL 64, Proto 17 (UDP), Checksum
    "7f000001"  # IP: Src 127.0.0.1
    "7f000001"  # IP: Dst 127.0.0.1
    "12345678"  # UDP: Src Port 4660, Dst Port 22136
    "000c0000"  # UDP: Len 12, Checksum
    "68656c6c6f"  # Payload: "hello"
)

# TCP header: Src Port 1234, Dst Port 80, Seq 1, Ack 0, Offset 5 (20 bytes), Flags 0x02 (SYN)
TCP_HEADER_HEX = (
    "04d2"  # Src Port 1234
    "0050"  # Dst Port 80
    "00000001"  # Seq 1
    "00000000"  # Ack 0
    "5002"  # Offset 5, Reserved 0, Flags 0x02 (SYN)
    "faf0"  # Window 64240
    "0000"  # Checksum (ignored for now)
    "0000"  # Urgent Pointer 0
)

# Ethernet (14 bytes) + ARP (28 bytes)
ARP_PACKET_HEX = (
    "ffffffffffff"  # Dest MAC
    "000c293e849d"  # Src MAC
    "0806"  # Type: ARP
    "00010800"  # HW Type: Ethernet, Proto: IPv4
    "06040001"  # HW Size 6, Proto Size 4, Op: Request (1)
    "000c293e849d"  # Sender MAC
    "c0a80101"  # Sender IP: 192.168.1.1
    "000000000000"  # Target MAC
    "c0a80102"  # Target IP: 192.168.1.2
)


@pytest.mark.parametrize(
    "packet_hex, addr, frame_id, expected_log_part",
    [
        (UDP_PACKET_HEX, ("eth0", 0), 0, "UDP: SRC_PORT: 4660, DST_PORT: 22136"),
        (ARP_PACKET_HEX, ("eth1", 0), 1, "SRC_HW_ADDR: 00:0c:29:3e:84:9d"),
    ],
)
def test_handle_frame_output(capsys, packet_hex, addr, frame_id, expected_log_part):
    packet_bytes = bytes.fromhex(packet_hex)
    handle_frame(packet_bytes, addr, frame_id)
    captured = capsys.readouterr()
    assert expected_log_part in captured.out
    assert f"Frame id: {frame_id}" in captured.out
    assert f"Interface: {addr[0]}" in captured.out


def test_l2_parsing():
    # 14 bytes Ethernet header
    data = bytes.fromhex("00112233445566778899aabb0800")
    l2 = L2Data(data)
    assert l2.dst_mac == "00:11:22:33:44:55"
    assert l2.src_mac == "66:77:88:99:aa:bb"
    assert l2.eth_type == "0800"


def test_udp_parsing():
    # 8 bytes UDP header: src 1234 (0x04d2), dst 5678 (0x162e), len 8, cksum 0
    data = bytes.fromhex("04d2162e00080000")
    udp = UDPData(data)
    assert udp.src_port == 1234
    assert udp.dst_port == 5678
    assert udp.length == 8


def test_tcp_parsing():
    data = bytes.fromhex(TCP_HEADER_HEX)
    tcp = TCPData(data)
    assert tcp.src_port == 1234
    assert tcp.dst_port == 80
    assert tcp.seq == 1
    assert tcp.ack == 0
    assert tcp.offset == 20
    assert tcp.flag_syn == 1
    assert tcp.flag_ack == 0


def test_icmp_parsing():
    # 4 bytes ICMP header: Type 8 (Echo Request), Code 0, Checksum 0xf7ff
    data = bytes.fromhex("0800f7ff")
    icmp = ICMPData(data)
    assert icmp.type == 8
    assert "Echo Request" in repr(icmp)


def test_tcp_parsing_with_flags_and_options():
    # TCP header: Src Port 1234, Dst Port 80, Seq 1, Ack 0,
    # Offset 8 (32 bytes -> 12 bytes of options), Flags 0x1C2 (NS, CWR, ECE, SYN)
    # 0x1C2 = 0b111000010
    # Flags: NS (1), CWR (1), ECE (1), URG (0), ACK (0), PSH (0), RST (0), SYN (1), FIN (0)
    tcp_header_hex = (
        "04d2"  # Src Port 1234
        "0050"  # Dst Port 80
        "00000001"  # Seq 1
        "00000000"  # Ack 0
        "81c2"  # Offset 8, Reserved 0, Flags 0x1C2
        "faf0"  # Window 64240
        "0000"  # Checksum
        "0000"  # Urgent Pointer
        "020405b40103030801010402"  # 12 bytes of options (MSS, WScale, SACK Permitted)
    )
    data = bytes.fromhex(tcp_header_hex)
    tcp = TCPData(data)
    assert tcp.src_port == 1234
    assert tcp.dst_port == 80
    assert tcp.offset == 32
    assert tcp.flag_ns == 1
    assert tcp.flag_cwr == 1
    assert tcp.flag_ece == 1
    assert tcp.flag_syn == 1
    assert tcp.flag_fin == 0
    assert tcp.options == "020405b40103030801010402"


def test_udp_repr_checksum_hex():
    data = bytes.fromhex("04d2162e0008abcd")
    udp = UDPData(data)
    assert "CHECKSUM: abcd" in repr(udp)
