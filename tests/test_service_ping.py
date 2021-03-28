# -*- coding: utf-8 -*-
"""Unit tests for service_ping."""
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

import unittest
from collections import defaultdict
from cotopaxi.common_utils import Protocol, get_local_ip
from cotopaxi.cotopaxi_tester import check_caps, TestParams
from cotopaxi.service_ping import main, service_ping
from .common_test_utils import (
    scrap_output,
    load_test_servers,
    load_test_servers_list,
    CotopaxiToolServerTester,
)
from .common_runner import TimerTestRunner


class TestServicePing(CotopaxiToolServerTester, unittest.TestCase):
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

    def test_main_basic_params_pos(self):
        output = scrap_output(main, ["::1", "10", "-P", "CoAP", "-T", "0.001"])
        self.assertIn("[+] Host ::1", output)
        self.assertIn("respond to ", output)
        self.assertIn(" message", output)

    def test_main_basic_params_ipv6_pos(self):
        output = scrap_output(main, ["127.0.0.1", "10", "-P", "CoAP", "-T", "0.001"])
        self.assertIn("[+] Host 127.0.0.1:10", output)
        self.assertIn("respond to ", output)
        self.assertIn(" message", output)

    def test_service_ping_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))

        config = load_test_servers()

        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        print("test_server_ip: {}".format(test_server_ip))

        test_params = TestParams()
        test_params.dst_endpoint.ip_addr = test_server_ip
        test_servers_proto = defaultdict(list)

        list_test_servers = load_test_servers_list()
        if not list_test_servers:
            print(
                "No remote servers in test_servers.yaml - remote tests not performed!"
            )
            return
        for server in list_test_servers:
            test_servers_proto[server["protocol"]].append(server)

        for proto in test_servers_proto.copy():
            # print("{} : {}".format(proto, test_servers_proto[proto]))
            proto_upper = proto.upper()
            test_params.protocol = Protocol[proto_upper]
            for server in test_servers_proto[proto_upper]:
                if server["ping"]:
                    test_params.dst_endpoint.port = int(server["port"])
                    result = service_ping(test_params)
                    if "version" in server:
                        server_name = "{} {}".format(server["name"], server["version"])
                    message = "Server: {} port: {} result: {}".format(
                        server_name, test_params.dst_endpoint.port, result
                    )
                    print(message)
                    self.assertTrue(result, message + " (not responding to ping)")

    def test_service_ping_mdns_pos(self):
        output = scrap_output(main, ["224.0.0.251", "15353", "-P", "mDNS"])
        self.assertIn("mDNS", output)

    def test_service_ping_ssdp_pos(self):
        output = scrap_output(main, ["224.0.0.251", "15353", "-P", "SSDP"])
        self.assertIn("SSDP", output)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
