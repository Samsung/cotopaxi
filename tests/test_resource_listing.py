# -*- coding: utf-8 -*-
"""Unit tests for resource_listing."""
#
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
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

    def test_main_empty(self):
        output = scrap_output(main, [])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_too_few_args(self):
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

    def test_main_help(self):
        output = scrap_output(main, ["-h"])
        self.assertIn("positional arguments", output)
        self.assertIn("show this help message and exit", output)

    def test_main_no_file(self):
        output = scrap_output(main, ["127.0.0.1", "10", "test", "-P", "CoAP"])
        self.assertIn("Cannot load names: [Errno 2] No such file or directory", output)

    def test_main_basic_params(self):
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

    def test_main_basic_params_ipv6(self):
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

    def test_resource_listing_coap(self):
        local_ip = get_local_ip()
        print ("ip: {}".format(local_ip))

        config = load_test_servers()

        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        port = config["CoAP_TEST_SERVERS"]["coapthon_port"]
        print ("test_server_ip: {} port: {}".format(test_server_ip, port))
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

    def test_resource_listing_mdns(self):
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

    def test_resource_listing_ssdp(self):
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

    def test_resource_listing_rtsp(self):
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
