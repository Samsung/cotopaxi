# -*- coding: utf-8 -*-
"""Unit tests for service_ping."""
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

import sys
import unittest
from collections import defaultdict

sys.path.append("..")

from ..common_utils import check_caps, Protocol, get_local_ip, TestParams
from ..service_ping import main, service_ping
from .common_test_utils import scrap_output, load_test_servers, load_test_servers_list
from .common_runner import TimerTestRunner


class TestServicePing(unittest.TestCase):
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
        output = scrap_output(main, ["10"])
        self.assertTrue(
            "error: too few arguments" in output
            or "error: the following arguments are required" in output
        )

    def test_main_help(self):
        output = scrap_output(main, ["-h"])
        self.assertIn("positional arguments", output)
        self.assertIn("show this help message and exit", output)

    def test_main_basic_params(self):
        output = scrap_output(main, ["::1", "10", "-P", "DTLS", "-T", "0.001"])
        self.assertIn("[+] Host ::1", output)
        self.assertIn("respond to ", output)
        self.assertIn(" message", output)

    def test_main_basic_params_ipv6(self):
        output = scrap_output(main, ["127.0.0.1", "10", "-P", "DTLS", "-T", "0.001"])
        self.assertIn("[+] Host 127.0.0.1:10", output)
        self.assertIn("respond to ", output)
        self.assertIn(" message", output)

    def test_service_ping(self):
        local_ip = get_local_ip()
        print ("ip: {}".format(local_ip))

        config = load_test_servers()

        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        print ("test_server_ip: {}".format(test_server_ip))

        test_params = TestParams()
        test_params.dst_endpoint.ip_addr = test_server_ip
        test_servers_proto = defaultdict(list)

        list_test_servers = load_test_servers_list()
        for server in list_test_servers:
            test_servers_proto[server["protocol"]].append(server)

        for proto in test_servers_proto:
            # print("{} : {}".format(proto, test_servers_proto[proto]))
            test_params.protocol = Protocol[proto]
            for server in test_servers_proto[proto]:
                if server["ping"]:
                    test_params.dst_endpoint.port = int(server["port"])
                    result = service_ping(test_params)
                    if "version" in server:
                        server_name = "{} {}".format(server["name"], server["version"])
                    print (
                        "Server: {} port: {} result: {}".format(
                            server_name, test_params.dst_endpoint.port, result
                        )
                    )
                    self.assertTrue(result)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
