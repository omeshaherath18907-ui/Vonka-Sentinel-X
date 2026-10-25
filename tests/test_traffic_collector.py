from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from app.services.traffic_collector import TrafficCollector


def test_collector_starts_with_zero_counters():
    collector = TrafficCollector(
        interface="Intel(R) Wi-Fi 6E AX211 160MHz"
    )

    result = collector.snapshot()

    assert result["capture_running"] is False
    assert result["packets_total"] == 0
    assert result["bytes_total"] == 0
    assert result["protocols"] == {}


def test_classifies_tcp_packet():
    packet = Ether() / IP() / TCP()

    assert TrafficCollector.classify_packet(packet) == "TCP"


def test_classifies_udp_packet():
    packet = Ether() / IP() / UDP()

    assert TrafficCollector.classify_packet(packet) == "UDP"


def test_updates_metadata_without_starting_capture():
    collector = TrafficCollector(interface="test-interface")
    packet = Ether() / IP() / TCP()
    expected_size = len(packet)

    collector._handle_packet(packet)
    result = collector.snapshot()

    assert result["packets_total"] == 1
    assert result["bytes_total"] == expected_size
    assert result["protocols"]["TCP"] == 1
    assert result["last_packet_at"] is not None
    assert result["capture_running"] is False
