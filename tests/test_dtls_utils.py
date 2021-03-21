# -*- coding: utf-8 -*-
"""Unit tests for DTLS utils."""
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

import codecs
import unittest

from cotopaxi.dtls_utils import (
    DTLSTester,
    DTLS,
    DTLS_1_0_HELLO_NMAP,
    prepare_dtls_test_packets,
    scrap_dtls_response,
)
from .common_runner import TimerTestRunner
from .test_protocol_tester import TestProtocolTester


class TestDTLSTester(TestProtocolTester):
    def __init__(self, *args, **kwargs):
        TestProtocolTester.__init__(self, *args, **kwargs)
        self.tester = DTLSTester()

    def test_dtls_parse_pos(self):
        data = codecs.decode(DTLS_1_0_HELLO_NMAP, "hex")
        dtls_packet = DTLS(data)
        dtls_packet_text = scrap_dtls_response(dtls_packet)
        self.assertIn("client_hello", dtls_packet_text)
        self.assertIn("DTLS_1_", dtls_packet_text)

    def test_prepare_dtls_test_packets_pos(self):
        data_samples = prepare_dtls_test_packets()
        self.assertTrue(len(data_samples) > 0)

    def test_dtls_parse_neg(self):
        dtls_packet = DTLS("")
        dtls_packet_text = scrap_dtls_response(dtls_packet)
        print(dtls_packet_text)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
