# -*- coding: utf-8 -*-
"""Unit tests for CoAP utils."""
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

from cotopaxi.coap_utils import CoAPTester
from .common_runner import TimerTestRunner
from .test_protocol_tester import TestProtocolTester


class TestCoAPTester(TestProtocolTester):
    def __init__(self, *args, **kwargs):
        TestProtocolTester.__init__(self, *args, **kwargs)
        self.tester = CoAPTester()


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
