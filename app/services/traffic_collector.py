from collections import Counter, deque
from datetime import datetime
from threading import Lock
from time import monotonic

from scapy.all import AsyncSniffer
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


class TrafficCollector:
    """Passive, metadata-only network traffic collector."""

    def __init__(self, interface: str, window_seconds: int = 10):
        if not interface or not interface.strip():
            raise ValueError("A network interface must be selected.")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1.")

        self.interface = interface
        self.window_seconds = window_seconds
        self._lock = Lock()
        self._sniffer = None
        self._running = False
        self._started_at = None
        self._packets_total = 0
        self._bytes_total = 0
        self._protocols = Counter()
        self._recent = deque()
        self._last_packet_at = None
        self._last_error = None

    @staticmethod
    def classify_packet(packet) -> str:
        """Classify a packet without storing its payload."""
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(IPv6):
            return "IPv6"
        if packet.haslayer(IP):
            return "IPv4"
        return "Other"

    def _handle_packet(self, packet) -> None:
        """Update counters only; never retain the packet itself."""
        now = monotonic()

        try:
            packet_size = len(packet)
            protocol = self.classify_packet(packet)
        except Exception:
            with self._lock:
                self._last_error = "A packet could not be classified."
            return

        with self._lock:
            self._packets_total += 1
            self._bytes_total += packet_size
            self._protocols[protocol] += 1
            self._recent.append((now, packet_size))
            self._last_packet_at = datetime.now().astimezone().isoformat(
                timespec="seconds"
            )

            cutoff = now - self.window_seconds
            while self._recent and self._recent[0][0] < cutoff:
                self._recent.popleft()

    def start(self) -> None:
        """Start capture on the explicitly selected interface."""
        with self._lock:
            if self._running:
                return
            self._last_error = None

        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
        )

        try:
            sniffer.start()
        except Exception as exc:
            with self._lock:
                self._last_error = f"{type(exc).__name__}: {exc}"
            raise RuntimeError(
                "Could not start packet capture. Check the interface, "
                "Npcap, and Windows permissions."
            ) from exc

        with self._lock:
            self._sniffer = sniffer
            self._running = True
            self._started_at = monotonic()

    def stop(self) -> None:
        """Stop capture and wait for the capture thread to finish."""
        with self._lock:
            sniffer = self._sniffer
            running = self._running

        if sniffer is not None and running:
            try:
                sniffer.stop(join=True)
            finally:
                with self._lock:
                    self._running = False
                    self._sniffer = None

    def snapshot(self) -> dict:
        """Return current counters and rolling traffic rates."""
        now = monotonic()

        with self._lock:
            cutoff = now - self.window_seconds
            while self._recent and self._recent[0][0] < cutoff:
                self._recent.popleft()

            recent_packets = len(self._recent)
            recent_bytes = sum(size for _, size in self._recent)

            elapsed = (
                max(0.0, now - self._started_at)
                if self._started_at is not None
                else 0.0
            )
            denominator = min(
                float(self.window_seconds),
                max(elapsed, 1.0),
            )

            return {
                "interface": self.interface,
                "capture_running": self._running,
                "packets_total": self._packets_total,
                "bytes_total": self._bytes_total,
                "packets_per_second": round(
                    recent_packets / denominator, 2
                ),
                "bytes_per_second": round(
                    recent_bytes / denominator, 2
                ),
                "protocols": dict(self._protocols),
                "last_packet_at": self._last_packet_at,
                "last_error": self._last_error,
            }
