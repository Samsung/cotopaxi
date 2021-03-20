# -*- coding: utf-8 -*-
"""Test runner."""
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

import time
from unittest.runner import TextTestResult, TextTestRunner


class TimerTestResult(TextTestResult):
    def __init__(self, *args, **kwargs):
        super(TimerTestResult, self).__init__(*args, **kwargs)
        self.test_timings = []
        self.test_start_time = 0

    def startTest(self, test):
        self.test_start_time = time.time()
        super(TimerTestResult, self).startTest(test)

    def addSuccess(self, test):
        elapsed = time.time() - self.test_start_time
        name = self.getDescription(test)
        self.test_timings.append((name, elapsed))
        super(TimerTestResult, self).addSuccess(test)

    def get_test_timings(self):
        return self.test_timings


class TimerTestRunner(TextTestRunner):
    def __init__(self, slow_test_threshold=2):
        self.slow_test_threshold = slow_test_threshold
        super(TimerTestRunner, self).__init__(resultclass=TimerTestResult)

    def run(self, test):
        result = super(TimerTestRunner, self).run(test)

        self.stream.writeln(
            "\nSlow tests (>{:.03}s):".format(float(self.slow_test_threshold))
        )
        for name, elapsed in result.get_test_timings():
            if elapsed > self.slow_test_threshold:
                self.stream.writeln("({:.03}s) {}".format(elapsed, name))

        self.stream.writeln(
            "\nQuick tests (<={:.03}s):".format(float(self.slow_test_threshold))
        )
        for name, elapsed in result.get_test_timings():
            if elapsed <= self.slow_test_threshold:
                self.stream.writeln("({:.03}s) {}".format(elapsed, name))

        return result
