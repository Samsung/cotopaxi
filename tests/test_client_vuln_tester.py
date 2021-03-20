# -*- coding: utf-8 -*-
"""Unit tests for client vulnerability_tester."""
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

import threading
import unittest
import timeout_decorator

from cotopaxi.client_vuln_tester import main
from cotopaxi.common_utils import get_random_high_port
from .common_runner import TimerTestRunner
from .common_test_utils import CotopaxiToolClientTester, poke_tcp_server, scrap_output


class TestClientVulnTester(CotopaxiToolClientTester, unittest.TestCase):
    def __init__(self, *args, **kwargs):
        CotopaxiToolClientTester.__init__(self, *args, **kwargs)
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.main = main

    @timeout_decorator.timeout(10)
    def test_main_basic_params_pos(self):
        server_port = get_random_high_port()
        poke_thread = threading.Thread(target=poke_tcp_server, args=[server_port])
        poke_thread.start()
        output = scrap_output(
            main, ["-V", "-P", "RTSP", "-SP", str(server_port), "--vuln", "TP-LINK_000"]
        )
        poke_thread.join()
        self.assertIn("Loaded 1 vulnerabilities for test", output)
        self.assertIn("Finished vulnerability testing", output)


if __name__ == "__main__":
    TEST_RUNNER = TimerTestRunner()
    unittest.main(testRunner=TEST_RUNNER)
