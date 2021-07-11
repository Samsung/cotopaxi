# -*- coding: utf-8 -*-
"""Unit tests for protocol fuzzer."""
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
from cotopaxi.common_utils import get_local_ip
from cotopaxi.cotopaxi_tester import check_caps
from cotopaxi.protocol_fuzzer import main
from .common_test_utils import scrap_output, load_test_servers, CotopaxiToolServerTester
from .common_runner import TimerTestRunner


class TestProtocolFuzzer(CotopaxiToolServerTester, unittest.TestCase):
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
        output = scrap_output(main, ["127.0.0.1", "10", "-V", "-T", "0.01", "-HD"])
        self.assertIn("--ignore-ping-check", output)
        self.assertIn("stopped", output)

    def test_main_no_ping_ipv6_neg(self):
        output = scrap_output(main, ["::1", "10", "-V", "-T", "0.01", "-HD"])
        self.assertIn("--ignore-ping-check", output)
        self.assertIn("stopped", output)

    def test_main_basic_params_pos(self):
        output = scrap_output(
            main,
            [
                "127.0.0.1",
                "10",
                "-V",
                "--ignore-ping-check",
                "-T",
                "0.01",
                "-C",
                "cotopaxi/fuzzing_corpus/coap_minimal",
            ],
        )
        self.assertIn("Finished protocol fuzzing", output)
        self.assertIn("Make sure you have permission", output)

    def test_protocol_fuzzer_coap_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))

        config = load_test_servers()
        if "CoAP_TEST_SERVERS" not in config or not config["CoAP_TEST_SERVERS"]:
            print("[!] No remote CoAP servers - remote tests not performed for CoAP!")
            return
        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        coap_servers = ["aiocoap"]
        for coap_server in coap_servers:
            port = config["CoAP_TEST_SERVERS"][coap_server + "_port"]
            print("test_server_ip: {} port: {}".format(test_server_ip, port))
            output = scrap_output(
                main,
                [
                    test_server_ip,
                    port,
                    "-P",
                    "CoAP",
                    "-HD",
                    "-C",
                    "cotopaxi/fuzzing_corpus/coap_minimal",
                ],
            )
            self.assertIn(" Payload ", output)
            self.assertIn("Finished protocol fuzzing", output)
            self.assertNotIn("Messages sent: 0", output)
            self.assertNotIn("0 / 0 / 0 ms", output)

    def test_protocol_fuzzer_dtls_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))

        config = load_test_servers()
        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        if "DTLS_TEST_SERVERS" not in config or not config["DTLS_TEST_SERVERS"]:
            print("No remote DTLS servers - remote tests not performed for DTLS!")
            return

        dtls_servers = ["gnutls"]
        for dtls_server in dtls_servers:
            port = config["DTLS_TEST_SERVERS"][dtls_server + "_port"]
            print("test_server_ip: {} port: {}".format(test_server_ip, port))
            output = scrap_output(
                main,
                [
                    test_server_ip,
                    port,
                    "-P",
                    "DTLS",
                    "-HD",
                    "-C",
                    "cotopaxi/fuzzing_corpus/dtls_minimal",
                ],
            )
            self.assertIn(" Payload ", output)
            self.assertIn("Finished protocol fuzzing", output)
            self.assertNotIn("Messages sent: 0", output)
            self.assertNotIn("0 / 0 / 0 ms", output)

    def test_protocol_fuzzer_mqtt_pos(self):
        local_ip = get_local_ip()
        print("ip: {}".format(local_ip))

        config = load_test_servers()
        if "MQTT_TEST_SERVERS" not in config or not config["MQTT_TEST_SERVERS"]:
            print("[!] No remote MQTT servers - remote tests not performed for MQTT!")
            return
        test_server_ip = config["COMMON"]["DEFAULT_IP"]
        mqtt_servers = ["mosquitto"]
        for mqtt_server in mqtt_servers:
            port = config["MQTT_TEST_SERVERS"][mqtt_server + "_port"]
            print("test_server_ip: {} port: {}".format(test_server_ip, port))
            output = scrap_output(
                main,
                [
                    test_server_ip,
                    port,
                    "-P",
                    "MQTT",
                    "-HD",
                    "-C",
                    "cotopaxi/fuzzing_corpus/mqtt_minimal",
                ],
            )
            self.assertIn(" Payload ", output)
            self.assertIn("Finished protocol fuzzing", output)
            self.assertNotIn("Messages sent: 0", output)
            self.assertNotIn("0 / 0 / 0 ms", output)

        output = scrap_output(
            main,
            [
                "127.0.0.1",
                "5353",
                "-P",
                "mDNS",
                "-C",
                "cotopaxi/fuzzing_corpus/mdns_minimal",
            ],
        )
        # print "\n" + 30 * "-" + "\n" + output + "\n" + 30 * "-" + "\n"
        self.assertIn("Fuzzing stopped", output)

"""
print(mutate_testcase("test.txt", "abcd", 0, 0, 88))
print(mutate_testcase("test.txt", "abcd", 0, 1, 88))
print(mutate_testcase("test.txt", "abcd", 0, 2, 88))
print(mutate_testcase("test.txt", "abcd", 0, 3, 88))
print(mutate_testcase("test.txt", "abcd", 0, 4, 88))
print(mutate_testcase("test.txt", "a", 0, 4, 88))
print(mutate_testcase("test", "abcd", 0, 0, 10))
print(mutate_testcase("new.test.txt", "abcd", 0, 0, 10))
print(mutate_testcase("brand.new.test.txt", "abcd", 0, 0, 10))
print(mutate_testcase("test.txt", "abcd", 1, 0, 88))
print(mutate_testcase("test.txt", "abcd", 1, 1, 88))
print(mutate_testcase("test.txt", "abcd", 1, 2, 88))
print(mutate_testcase("test.txt", "abcd", 1, 3, 88))
print(mutate_testcase("test.txt", "abcd", 1, 4, 88))
print(mutate_testcase("test.txt", "abcd", 2, 0, 88))
print(mutate_testcase("test.txt", "abcd", 2, 1, 88))
print(mutate_testcase("test.txt", "abcd", 2, 2, 88))
print(mutate_testcase("test.txt", "abcd", 2, 3, 88))
print(mutate_testcase("test.txt", "abcd", 2, 4, 88))
print(mutate_testcase("test.txt", "abcd", 3, 0, 88))
print(mutate_testcase("test.txt", "abcd", 3, 1, 88))
print(mutate_testcase("test.txt", "abcd", 3, 2, 88))
print(mutate_testcase("test.txt", "abcd", 3, 3, 88))
print(mutate_testcase("test.txt", "abcd", 3, 4, 88))
print(mutate_testcase("test.txt", "abcd", 4, 0, 88))
print(mutate_testcase("test.txt", "abcd", 4, 1, 88))
print(mutate_testcase("test.txt", "abcd", 4, 2, 88))
print(mutate_testcase("test.txt", "abcd", 4, 3, 88))
print(mutate_testcase("test.txt", "abcd", 4, 4, 88))

('test_rem_0.txt', 'bcd')
('test_rem_1.txt', 'acd')
('test_rem_2.txt', 'abd')
('test_rem_3.txt', 'abc')
('test_rem_0.txt', 'bcd')
('test_rem_0.txt', 'X')
('test_rem_0', 'bcd')
('new.test_rem_0.txt', 'bcd')
('brand.new.test_rem_0.txt', 'bcd')
('test_cut_0.txt', 'X')
('test_cut_1.txt', 'a')
('test_cut_2.txt', 'ab')
('test_cut_3.txt', 'abc')
('test_cut_0.txt', 'X')
('test_flip_0.txt', 'Xbcd')
('test_flip_1.txt', 'aXcd')
('test_flip_2.txt', 'abXd')
('test_flip_3.txt', 'abcX')
('test_flip_0.txt', 'Xbcd')
('test_ins_0.txt', 'Xabcd')
('test_ins_1.txt', 'aXbcd')
('test_ins_2.txt', 'abXcd')
('test_ins_3.txt', 'abcXd')
('test_ins_0.txt', 'Xabcd')
('test_dup_0.txt', 'aabcd')
('test_dup_1.txt', 'abbcd')
('test_dup_2.txt', 'abccd')
('test_dup_3.txt', 'abcdd')
('test_dup_0.txt', 'aabcd')


"""

if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
