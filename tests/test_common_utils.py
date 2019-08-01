# -*- coding: utf-8 -*-
"""Unit tests for common_utils."""
#
#    Copyright (C) 2019 Samsung Electronics. All Rights Reserved.
#       Author: Jakub Botwicz (Samsung R&D Poland)
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
import sys

sys.path.append("..")
from .common_test_utils import scrap_output
from ..common_utils import (
    get_local_ip,
    get_local_ipv6_address,
    prepare_ips,
    prepare_ports,
    parse_port,
    get_random_high_port,
)
from .common_runner import TimerTestRunner


class TestCommonUtils(unittest.TestCase):
    def test_get_local_ip(self):
        local_ip = get_local_ip()
        print ("ip: {}".format(local_ip))
        print ("len(ip): {}".format(len(local_ip)))
        print ("ip.count('.'): {}".format(local_ip.count(".")))
        self.assertIsNotNone(local_ip)
        self.assertGreater(len(local_ip), 7)
        self.assertEqual(local_ip.count("."), 3)

    def test_get_local_ipv6(self):
        local_ip = get_local_ipv6_address()
        print ("ipv6: {}".format(local_ip))
        print ("len(ipv6): {}".format(len(local_ip)))
        print ("ipv6.count(':'): {}".format(local_ip.count(":")))
        self.assertIsNotNone(local_ip)
        # self.assertGreater(len(local_ip), 7)
        self.assertGreater(local_ip.count(":"), 0)

    def test_get_random_high_port(self):
        port = get_random_high_port()
        print ("port: {}".format(port))
        self.assertIsNotNone(port)
        self.assertGreater(int(port), 1024)
        self.assertLess(int(port), 65535)

    def test_prepare_ips(self):
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

    def test_prepare_ports(self):
        result = prepare_ports("101,103-105,104,242")
        expected = [101, 103, 104, 105, 242]
        self.assertListEqual(result, expected)

        result = prepare_ports("1,1,10,3-10,5,10,4,2,4,2")
        expected = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        self.assertListEqual(result, expected)

    def test_parse_port(self):
        output = scrap_output(parse_port, "101,103-105,104,242")
        # expected = None
        # self.assertEqual(result, expected)
        self.assertIn("Could not parse port: invalid literal for int", output)

        result = parse_port("1")
        expected = 1
        self.assertEqual(result, expected)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
