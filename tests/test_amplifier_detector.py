# -*- coding: utf-8 -*-
"""Unit tests for amplifier_detector."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Author: Jakub Botwicz
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

import unittest

from scapy.all import IP, UDP
from cotopaxi.amplifier_detector import main, ReflectorSniffer, amplifier_parse_args
from cotopaxi.cotopaxi_tester import check_caps
from .common_test_utils import scrap_output
from .common_runner import TimerTestRunner


class TestAmplifierDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            scrap_output(check_caps(), [])
        except SystemExit:
            exit(
                "This test suite requires admin permissions on network interfaces.\n"
                "On Linux and Unix run it with sudo, use root account (UID=0) "
                "or add CAP_NET_ADMIN, CAP_NET_RAW manually!\n"
                "On Windows run as Administrator."
            )

    def test_reflector_sniffer_pos(self):

        args = ["8.8.8.8", "-I", "0"]
        options = amplifier_parse_args(args)
        sniffer = ReflectorSniffer(options)

        packet = IP() / UDP()
        result = sniffer.filter_action(packet)
        self.assertMultiLineEqual(
            result,
            "TARGET: 8.8.8.8 | TO TARGET packets: 0, bytes: 0 | FROM "
            "TARGET packets: 0, bytes: 0 | AMPLIF FACTOR: 0.00%",
        )

        packet = IP(src="1.1.1.1", dst="8.8.8.8") / UDP(dport=1000, sport=2000)
        result = sniffer.filter_action(packet)
        self.assertIn("-100.00%", result)
        self.assertIn(" 28 ", result)

        packet = IP(src="8.8.8.8", dst="1.1.1.1") / UDP(dport=1000, sport=2000)
        result = sniffer.filter_action(packet)
        self.assertIn(" 28 ", result)
        self.assertIn(" 0.00%", result)

    def test_main_empty_neg(self):
        output = scrap_output(main, [])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_help_pos(self):
        output = scrap_output(main, ["-h"])
        self.assertIn("positional arguments", output)
        self.assertIn("show this help message and exit", output)

    def test_main_basic_pos(self):
        output = scrap_output(main, ["192.168.0.100", "-N", "0"])
        self.assertIn("Starting sniffing with filter", output)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
