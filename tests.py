# Run with: python -m unittest tests.py
# Run with: python -m unittest tests.PacketUtilTests.test_replay_ValidationRun_pcapng_produces_output

import os
import shutil
import unittest

from scapy.all import IP, TCP, UDP, Raw, rdpcap
import packetUtil


class PacketUtilTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Remember original output dir so we can restore it after all tests (if needed)
        cls.original_output_dir = packetUtil.OUTPUT_DIR

    def setUp(self):
        # Use a separate folder for test output
        self.test_dir = "test_output"

        # Always start clean: remove if it exists, then recreate
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
        os.makedirs(self.test_dir, exist_ok=True)

        # Point packetUtil to the test directory
        packetUtil.OUTPUT_DIR = self.test_dir

    # === Unit tests for packet_handler ===

    def test_tcp_packet_with_payload_creates_file_with_correct_hex(self):
        """
        A TCP packet with a Raw payload should create exactly one file
        whose name contains the 4-tuple and whose content is the hex
        encoding of the payload bytes.
        """
        payload = b"HelloWorld"
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / \
              TCP(sport=1234, dport=80) / \
              Raw(payload)

        packetUtil.packet_handler(pkt)

        files = os.listdir(self.test_dir)
        # Exactly one file should be created
        self.assertEqual(len(files), 1)

        fname = files[0]
        # File name should contain src/dst IP and ports
        self.assertIn("10.0.0.1.1234-10.0.0.2.80", fname)

        # File content should be payload.hex()
        path = os.path.join(self.test_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            data = f.read().strip()

        self.assertEqual(data, payload.hex())

    def test_zero_payload_tcp_packet_creates_no_file(self):
        """
        A TCP packet with no Raw payload (pure ACK etc.) should not
        create any output file.
        """
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / \
              TCP(sport=1234, dport=80)

        packetUtil.packet_handler(pkt)

        files = os.listdir(self.test_dir)
        self.assertEqual(files, [])

    def test_non_tcp_packet_is_ignored(self):
        """
        A non-TCP packet (e.g., UDP) must be ignored by packet_handler
        and produce no output file.
        """
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / \
              UDP(sport=1234, dport=53)

        packetUtil.packet_handler(pkt)

        files = os.listdir(self.test_dir)
        self.assertEqual(files, [])

    # === Integration-style test with ValidationRun.pcapng ===

    def test_replay_ValidationRun_pcapng_produces_output(self):
        """
        Replay packets from ValidationRun.pcapng through packet_handler.
        The test passes if at least one TCP packet in the capture
        leads to at least one output file and no exceptions are raised.
        """
        pcap_path = "ValidationRun.pcapng"

        if not os.path.exists(pcap_path):
            self.skipTest("ValidationRun.pcapng not found in current directory")

        packets = rdpcap(pcap_path)

        # Just process the first 100 packets to limit test time
        for pkt in packets[:100]:
            packetUtil.packet_handler(pkt)

        files = os.listdir(self.test_dir)
        self.assertGreater(len(files), 0)


if __name__ == "__main__":
    unittest.main()
