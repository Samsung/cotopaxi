# -*- coding: utf-8 -*-
"""Unit tests for protocol tester."""
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
from cotopaxi.protocol_tester import ProtocolTester
from .common_runner import TimerTestRunner


class TestProtocolTester(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.tester = ProtocolTester()

    def test_tester_names_pos(self):
        short_name = self.tester.protocol_short_name()
        self.assertIsInstance(short_name, str)

        full_name = self.tester.protocol_full_name()
        self.assertIsInstance(full_name, str)

    def test_tester_port_pos(self):
        default_port = self.tester.default_port()
        self.assertIsInstance(default_port, int)

    def test_tester_implements_pos(self):
        self.assertIsInstance(self.tester.implements_service_ping(), bool)
        self.assertIsInstance(self.tester.implements_fingerprinting(), bool)
        self.assertIsInstance(self.tester.implements_resource_listing(), bool)
        self.assertIsInstance(self.tester.implements_server_fuzzing(), bool)
        self.assertIsInstance(self.tester.implements_client_fuzzing(), bool)
        self.assertIsInstance(self.tester.implements_active_scanning(), bool)
        self.assertIsInstance(self.tester.implements_vulnerability_testing(), bool)

    def test_tester_protocol_pos(self):
        protocol = self.tester.transport_protocol()
        self.assertTrue(protocol in [None, TCP, UDP])

    def test_tester_parsers_pos(self):
        parser = self.tester.request_parser()
        if parser:
            show_method = getattr(parser, "show", None)
            self.assertTrue(callable(show_method))
        parser = self.tester.response_parser()
        if parser:
            show_method = getattr(parser, "show", None)
            self.assertTrue(callable(show_method))

    def test_tester_operations_pos(self):
        self.tester.ping(None)
        self.tester.fingerprint(None)
        self.tester.resource_listing(None, None)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
