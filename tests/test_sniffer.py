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
)


def test_parse_args_defaults():
    args = parse_args([])
    assert args.count == 0
    assert args.interface is None
    assert args.interactive is False


@pytest.mark.parametrize(
    "args_list, expected_count, expected_interface",
    [
        (["--count", "10"], 10, None),
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


def test_icmp_parsing():
    # 4 bytes ICMP header: Type 8 (Echo Request), Code 0, Checksum 0xf7ff
    data = bytes.fromhex("0800f7ff")
    icmp = ICMPData(data)
    assert icmp.type == 8
    assert "Echo Request" in repr(icmp)
