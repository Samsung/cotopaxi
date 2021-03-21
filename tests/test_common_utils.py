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

from cotopaxi.common_utils import (
    get_local_ip,
    get_local_ipv6_address,
    get_random_high_port,
)
from .common_runner import TimerTestRunner


class TestCommonUtils(unittest.TestCase):
    def test_get_local_ip_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))
        print("len(ip): {}".format(len(local_ip)))
        print("ip.count('.'): {}".format(local_ip.count(".")))
        self.assertIsNotNone(local_ip)
        self.assertGreater(len(local_ip), 7)
        self.assertEqual(local_ip.count("."), 3)

    def test_get_local_ipv6_pos(self):
        local_ip = get_local_ipv6_address()
        print("ipv6: {}".format(local_ip))
        print("len(ipv6): {}".format(len(local_ip)))
        print("ipv6.count(':'): {}".format(local_ip.count(":")))
        self.assertIsNotNone(local_ip)
        # self.assertGreater(len(local_ip), 7)
        self.assertGreater(local_ip.count(":"), 0)

    def test_get_random_high_port_pos(self):
        port = get_random_high_port()
        print("port: {}".format(port))
        self.assertIsNotNone(port)
        self.assertGreater(int(port), 1024)
        self.assertLess(int(port), 65535)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
