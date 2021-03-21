# -*- coding: utf-8 -*-
"""Unit tests for active_scanner."""
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

import timeout_decorator
import unittest

from cotopaxi.active_scanner import main, DTLSScanner
from cotopaxi.common_utils import get_local_ip
from cotopaxi.cotopaxi_tester import check_caps, TestParams
from .common_test_utils import scrap_output, load_test_servers, CotopaxiToolServerTester
from .common_runner import TimerTestRunner


class TestActiveScanner(CotopaxiToolServerTester, unittest.TestCase):
    def __init__(self, *args, **kwargs):
        CotopaxiToolServerTester.__init__(self, *args, **kwargs)
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.main = main

    def test_main_empty_neg(self):
        output = scrap_output(main, [])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_too_few_args_neg(self):
        output = scrap_output(main, ["10"])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_help_pos(self):
        output = scrap_output(main, ["-h"])
        self.assertIn("positional arguments", output)
        self.assertIn("show this help message and exit", output)

    def test_main_no_ping_neg(self):
        output = scrap_output(main, ["127.0.0.1", "10", "-V", "-T", "0.001"])
        self.assertIn("--ignore-ping-check", output)
        self.assertIn("skipping", output)

    def test_main_no_ping_ipv6_neg(self):
        output = scrap_output(main, ["::1", "10", "-V", "-T", "0.001"])
        self.assertIn("--ignore-ping-check", output)
        self.assertIn("skipping", output)

    def test_active_scanner_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))

        config = load_test_servers()
        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        if "DTLS_TEST_SERVERS" not in config:
            print("No remote DTLS servers - remote tests not performed!")
            return
        dtls_servers = ["matrix"]
        for dtls_server in dtls_servers:
            port = config["DTLS_TEST_SERVERS"][dtls_server + "_port"]
            print("test_server_ip: {} port: {}".format(test_server_ip, port))
            output = scrap_output(main, [test_server_ip, port, "-P", "DTLS"])
            self.assertIn("PSK_WITH_AES_256_CBC_SHA384", output)
            self.assertIn("DTLS_1_1 (0xfefd)", output)
            self.assertIn("NULL (0x0000)", output)
            self.assertIn("Finished active security scanning", output)
            self.assertIn("Starting scan: supported_protocol_versions", output)
            self.assertIn("Supported protocol versions", output)

    @timeout_decorator.timeout(2)
    def not_test_dtls_scanner_sniff_pos(self):
        scanner = DTLSScanner(TestParams())
        scanner.sniff(timeout=0.0001)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
