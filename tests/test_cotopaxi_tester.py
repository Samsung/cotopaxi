# -*- coding: utf-8 -*-
"""Unit tests for common_utils."""
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
from scapy.all import TCP, UDP
from cotopaxi.common_utils import Protocol
from cotopaxi.cotopaxi_tester import (
    prepare_ips,
    prepare_ports,
    parse_port,
    protocols_using,
)
from .common_test_utils import scrap_output
from .common_runner import TimerTestRunner


class TestCotopaxiTester(unittest.TestCase):
    def test_prepare_ips_pos(self):
        result = prepare_ips("3.3.3.3,1.1.1.1,2.2.2.2")
        expected = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        self.assertListEqual(result, expected)

        result = prepare_ips(
            "3e80::5265:f3ff:fe2a:285b,1e80:5265::f3ff:fe2a:285b,2e80:5265:f3ff:fe2a::285b"
        )
        expected = [
            "1e80:5265::f3ff:fe2a:285b",
            "2e80:5265:f3ff:fe2a::285b",
            "3e80::5265:f3ff:fe2a:285b",
        ]
        self.assertListEqual(result, expected)

        result = prepare_ips("3e80::5265:f3ff:fe2a:285b/118")
        self.assertEqual(len(result), 1024)

        result = prepare_ips("10.0.0.0/22")
        self.assertEqual(len(result), 1024)

        result = prepare_ips("2.2.2.2/31,1.1.1.1,2.2.2.2,1.1.1.2/31")
        expected = ["1.1.1.1", "1.1.1.2", "1.1.1.3", "2.2.2.2", "2.2.2.3"]
        self.assertListEqual(result, expected)

    def test_prepare_ports_pos(self):
        result = prepare_ports("101,103-105,104,242")
        expected = [101, 103, 104, 105, 242]
        self.assertListEqual(result, expected)

        result = prepare_ports("1,1,10,3-10,5,10,4,2,4,2")
        expected = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        self.assertListEqual(result, expected)

    def test_parse_port_neg(self):
        output = scrap_output(parse_port, "101,103-105,104,242")
        # expected = None
        # self.assertEqual(result, expected)
        self.assertIn("Could not parse port: invalid literal for int", output)

    def test_parse_port_pos(self):

        result = parse_port("1")
        expected = 1
        self.assertEqual(result, expected)

    def test_protocols_using_pos(self):
        udp_protos = protocols_using(UDP)
        self.assertGreaterEqual(len(udp_protos), 4)
        self.assertTrue(Protocol.COAP in udp_protos)
        self.assertTrue(Protocol.RTSP not in udp_protos)
        for proto in udp_protos:
            self.assertIsInstance(proto, Protocol)
        tcp_protos = protocols_using(TCP)
        self.assertGreaterEqual(len(tcp_protos), 4)
        for proto in tcp_protos:
            self.assertIsInstance(proto, Protocol)
        self.assertTrue(Protocol.RTSP in tcp_protos)
        self.assertTrue(Protocol.COAP not in tcp_protos)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
