# -*- coding: utf-8 -*-
"""Unit tests for device_identification."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Mariusz Księżak (Samsung R&D Poland), Jakub Botwicz
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
    from cotopaxi.device_identification import main
    from .common_test_utils import scrap_output
    from .common_runner import TimerTestRunner

    SKIP_TESTS = False
except SyntaxError:
    if sys.version_info[0] < 3:
        SKIP_TESTS = True
    else:
        sys.exit("Syntax error on loading dependencies!")


@unittest.skipIf(SKIP_TESTS, "Skipped tests for Python3!")
class TestDeviceIdentification(unittest.TestCase):
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

    def test_main_basic_ipv4_pos(self):
        output = scrap_output(
            main, ["tests/traffic_samples/chrissanders.org_http_post.pcapng"]
        )
        self.assertIn("Loaded 21 packets from the provided file", output)
        self.assertIn("Device was classified as", output)
        self.assertIn("172.16.16.128", output)
        self.assertIn("Finished device identification", output)

    def test_main_basic_arp_pos(self):
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
        self.assertIn("Finished device identification", output)

    def test_main_basic_ipv4_neg(self):
        output = scrap_output(
            main,
            [
                "tests/traffic_samples/chrissanders.org_http_post.pcapng",
                "-I",
                "10.10.10.10",
            ],
        )
        self.assertIn("Loaded 21 packets from the provided file", output)
        self.assertIn(
            "Not enough packets with IP 10.10.10.10 in the provided data capture",
            output,
        )
        self.assertIn("Finished device identification", output)

    def test_main_basic_ipv6_pos(self):
        output = scrap_output(main, ["tests/traffic_samples/coap_over_ipv6.pcap", "-V"])
        self.assertIn("Loaded 10 packets from the provided file", output)
        self.assertIn("Device was classified as", output)
        self.assertIn("bbbb::3", output)
        self.assertIn("Finished device identification", output)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
