# -*- coding: utf-8 -*-
"""Unit tests for resource_listing."""
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

import timeout_decorator
import unittest

from cotopaxi.resource_listing import main
from cotopaxi.common_utils import get_local_ip
from cotopaxi.cotopaxi_tester import check_caps
from .common_test_utils import scrap_output, load_test_servers, CotopaxiToolServerTester
from .common_runner import TimerTestRunner


class TestResourceListing(unittest.TestCase, CotopaxiToolServerTester):
    def __init__(self, *args, **kwargs):
        CotopaxiToolServerTester.__init__(self, *args, **kwargs)
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.main = main

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

    def test_main_empty_neg(self):
        output = scrap_output(main, [])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_too_few_args_neg(self):
        output = scrap_output(main, ["127.0.0.1"])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )
        output = scrap_output(main, ["127.0.0.1", "10"])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_help_pos(self):
        output = scrap_output(main, ["-h"])
        self.assertIn("positional arguments", output)
        self.assertIn("show this help message and exit", output)

    def test_main_no_file_neg(self):
        output = scrap_output(main, ["127.0.0.1", "10", "test", "-P", "CoAP"])
        self.assertIn("Cannot load names: [Errno 2] No such file or directory", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_ip_nonint_neg(self):
        output = scrap_output(self.main, ["a.b.c.d", "40000", "abc"])
        self.assertIn("Cannot parse IP address", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_ip_5_octets_neg(self):
        output = scrap_output(self.main, ["1.2.3.4.5", "40000", "abc"])
        self.assertIn("Cannot parse IP address", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_port_nonint_neg(self):
        output = scrap_output(self.main, ["10.10.10.10", "aaaaa", "abc"])
        self.assertIn("Cannot parse port", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_port_negint_neg(self):
        output = scrap_output(self.main, ["10.10.10.10", "-10", "abc"])
        self.assertIn("Cannot parse port", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_port_bigint_neg(self):
        output = scrap_output(self.main, ["10.10.10.10", "999999", "abc"])
        self.assertIn("Port not in range", output)

    def test_main_basic_params_pos(self):
        output = scrap_output(
            main,
            [
                "127.0.0.1",
                "10",
                "cotopaxi/lists/urls/short_url_list.txt",
                "-P",
                "CoAP",
                "-T",
                "0.001",
            ],
        )
        self.assertIn("available on server 127.0.0.1:10 for method GET", output)

    def test_main_basic_params_ipv6_pos(self):
        output = scrap_output(
            main,
            [
                "::1",
                "10",
                "cotopaxi/lists/urls/short_url_list.txt",
                "-P",
                "CoAP",
                "-T",
                "0.001",
            ],
        )
        self.assertIn("available on server ::1:10 for method GET", output)

    def test_resource_listing_coap_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))

        config = load_test_servers()
        if "CoAP_TEST_SERVERS" not in config or not config["CoAP_TEST_SERVERS"]:
            print("No remote CoAP servers - remote tests not performed!")
            return
        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        port = config["CoAP_TEST_SERVERS"]["coapthon_port"]
        print("test_server_ip: {} port: {}".format(test_server_ip, port))
        output = scrap_output(
            main,
            [
                test_server_ip,
                port,
                "cotopaxi/lists/urls/short_url_list.txt",
                "-P",
                "CoAP",
            ],
        )
        self.assertIn("Url |big| received code |2_05| on server", output)
        self.assertIn("Url |test| is not available on server", output)

        output = scrap_output(
            main,
            [
                test_server_ip,
                port,
                "cotopaxi/lists/urls/short_url_list.txt",
                "-M",
                "ALL",
                "-P",
                "CoAP",
            ],
        )
        self.assertIn("for method GET", output)
        self.assertIn("for method POST", output)
        self.assertIn("for method PUT", output)
        self.assertIn("for method DELETE", output)

        output = scrap_output(
            main,
            [
                test_server_ip,
                port,
                "cotopaxi/lists/urls/short_url_list.txt",
                "-M",
                "PUT",
                "DELETE",
                "-P",
                "CoAP",
            ],
        )
        self.assertNotIn("for method GET", output)
        self.assertNotIn("for method POST", output)
        self.assertIn("for method PUT", output)
        self.assertIn("for method DELETE", output)

    def resource_listing(self, server_name, server_ver):
        test_server_ip = str(self.config["COMMON"]["DEFAULT_IP"])
        test_server_port = next(
            x
            for x in self.test_servers
            if x["name"] == server_name and x["version"] == server_ver
        )["port"]

        return scrap_output(main, [test_server_ip, str(test_server_port), "-P", "mDNS"])

    def test_resource_listing_mdns_pos(self):
        output = scrap_output(
            main,
            [
                "225.0.0.225",
                "5353",
                "cotopaxi/lists/urls/short_url_list.txt",
                "-P",
                "mDNS",
                "-T",
                "0.001",
            ],
        )
        self.assertIn("Finished resource listing", output)
        self.assertIn("is not responding for query", output)

    def test_resource_listing_ssdp_pos(self):
        output = scrap_output(
            main,
            [
                "225.0.0.225",
                "5353",
                "cotopaxi/lists/urls/short_url_list.txt",
                "-P",
                "SSDP",
                "-T",
                "0.001",
            ],
        )
        self.assertIn("Finished resource listing", output)
        self.assertIn("Inactive endpoints: 2", output)

    def test_resource_listing_rtsp_pos(self):
        output = scrap_output(
            main,
            [
                "225.0.0.225",
                "5353",
                "cotopaxi/lists/urls/short_url_list.txt",
                "-P",
                "RTSP",
                "-T",
                "0.001",
            ],
        )
        self.assertIn("Finished resource listing", output)
        self.assertIn("Inactive endpoints: 2", output)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
