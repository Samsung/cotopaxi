# -*- coding: utf-8 -*-
"""Tool for vulnerability testing of network clients."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz, Michał Radwański
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

import os
import sys
from scapy.all import TCP, UDP

from .client_proto_fuzzer import TCPFuzzer, UDPFuzzer
from .cotopaxi_tester import CotopaxiClientTester, protocols_using
from .vulnerability_tester import VULNS, bypass_list, select_vulnerabilities


def main(args):
    """Start client vulnerability testing based on command line parameters."""
    bypass_list(args)

    tester = CotopaxiClientTester("vulnerability testing")
    selected_vulns = select_vulnerabilities(tester, args)

    test_vulns = []
    if selected_vulns == ["ALL"]:
        for vuln_name in VULNS:
            vuln = VULNS[vuln_name]
            if vuln.protocol == tester.test_params.protocol:
                vuln.payload_file = (
                    os.path.dirname(__file__) + "/vulnerabilities/" + vuln.payload_file
                )
                test_vulns.append(vuln)
    else:
        for vuln_name in VULNS:
            vuln = VULNS[vuln_name]
            if vuln_name in selected_vulns:
                vuln.payload_file = (
                    os.path.dirname(__file__) + "/vulnerabilities/" + vuln.payload_file
                )
                test_vulns.append(vuln)

    print("Loaded {} vulnerabilities for test".format(len(test_vulns)))

    if tester.test_params.protocol in protocols_using(UDP):
        server = UDPFuzzer(tester.test_params)
        server.perform_fuzzing(test_vulns)
    elif tester.test_params.protocol in protocols_using(TCP):
        server = TCPFuzzer(tester.test_params)
        server.perform_fuzzing(test_vulns)
    else:
        print(
            "Protocol {} is not supported by this tool!".format(
                tester.test_params.protocol
            )
        )


if __name__ == "__main__":
    main(sys.argv[1:])
