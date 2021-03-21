# -*- coding: utf-8 -*-
"""Unit tests for traffic_analyzer."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz
#
#    This file is part of Cotopaxi.
#
#    Cotopaxi is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    Cotopaxi is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Cotopaxi.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import unittest

try:
    from cotopaxi.traffic_analyzer import main
    from .common_test_utils import scrap_output
    from .common_runner import TimerTestRunner
except SyntaxError:
    sys.exit("[!] This set of test must be run using Python 3!")


class TestTrafficAnalyzer(unittest.TestCase):
    def test_main_empty_neg(self):
        output = scrap_output(main, [])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_help_neg(self):
        output = scrap_output(main, ["-h"])
        self.assertIn("positional arguments", output)
        self.assertIn("show this help message and exit", output)

    def test_main_http_traffic_pos(self):
        output = scrap_output(
            main, ["tests/traffic_samples/chrissanders.org_http_post.pcapng"]
        )
        self.assertIn("Loaded 21 packets from the provided file", output)
        self.assertIn("Traffic was classified as", output)
        self.assertIn("HTTP", output)
        self.assertIn("172.16.16.128", output)
        self.assertIn("Finished traffic analysis", output)

    def test_main_arp_traffic_pos(self):
        output = scrap_output(
            main,
            [
                "tests/traffic_samples/chrissanders.org_arp_resolution.pcapng",
                "-I",
                "10.10.10.10",
                "--max",
                "10",
                "--min",
                "10",
            ],
        )
        self.assertIn("Loaded 2 packets from the provided file", output)
        self.assertIn("Finished traffic analysis", output)

    def test_main_ultimate_pcap_pos(self):
        output = scrap_output(
            main,
            [
                "tests/traffic_samples/webweblog.net_Ultimate_PCAP_v20200224.pcapng",
                "-I",
                "192.168.121.253",
            ],
        )
        self.assertIn("Loaded 1000 packets from the provided file", output)
        self.assertIn("FTP", output)
        self.assertIn("IPv4", output)
        self.assertIn("UDP", output)
        self.assertIn("HSRP", output)
        self.assertIn("192.168.121.253", output)
        self.assertIn("Finished traffic analysis", output)
        self.assertIn("Classification time:", output)

    def test_main_max_packets_pos(self):
        output = scrap_output(
            main,
            [
                "tests/traffic_samples/chrissanders.org_http_post.pcapng",
                "--max",
                "10",
            ],
        )
        self.assertIn("Loaded 21 packets from the provided file", output)
        self.assertIn("Found 10 packets", output)
        self.assertIn("IPv4", output)
        self.assertIn("Finished traffic analysis", output)
        self.assertIn("Classification time:", output)

    def test_main_min_packets_pos(self):
        output = scrap_output(
            main,
            [
                "tests/traffic_samples/chrissanders.org_http_post.pcapng",
                "--min",
                "100",
            ],
        )
        self.assertIn("Loaded 21 packets from the provided file", output)
        self.assertNotIn("Found", output)
        self.assertNotIn("IPv4", output)
        self.assertIn("Finished traffic analysis", output)
        self.assertIn("Classification time:", output)

    def test_main_ipv6_traffic_pos(self):
        output = scrap_output(main, ["tests/traffic_samples/coap_over_ipv6.pcap", "-V"])
        self.assertIn("Loaded 10 packets from the provided file", output)
        self.assertIn("Traffic was classified as", output)
        self.assertIn("IPv6", output)
        self.assertIn("bbbb::3", output)
        self.assertIn("Finished traffic analysis", output)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
