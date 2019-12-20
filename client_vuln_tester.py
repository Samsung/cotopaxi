# -*- coding: utf-8 -*-
"""Tool for vulnerability testing of network clients."""
#
#    Copyright (C) 2019 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz (Samsung R&D Poland)
#                Michał Radwański (Samsung R&D Poland)
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

from .client_proto_fuzzer import tcp_server, udp_server
from .common_utils import CotopaxiClientTester, Protocol
from .vulnerability_tester import VULNS, bypass_list, select_vulnerabilities


def main(args):
    """Starts client vulnerability testing based on command line parameters"""
    bypass_list(args)

    tester = CotopaxiClientTester("vulnerability testing")
    selected_vulns = select_vulnerabilities(tester, args)

    test_vulns = []
    if selected_vulns == ["ALL"]:
        for vuln_name in VULNS:
            vuln = VULNS[vuln_name]
            if vuln.protocol == tester.test_params.protocol:
                vuln.payload_file = "cotopaxi/vulnerabilities/" + vuln.payload_file
                test_vulns.append(vuln)
    else:
        for vuln_name in VULNS:
            vuln = VULNS[vuln_name]
            if vuln_name in selected_vulns:
                vuln.payload_file = "cotopaxi/vulnerabilities/" + vuln.payload_file
                test_vulns.append(vuln)

    print ("Loaded {} vulnerabilities for test".format(len(test_vulns)))

    if tester.test_params.protocol in [Protocol.CoAP, Protocol.DTLS, Protocol.mDNS]:
        udp_server(tester.test_params, test_vulns)
    elif tester.test_params.protocol in [Protocol.MQTT, Protocol.HTCPCP, Protocol.RTSP]:
        tcp_server(tester.test_params, test_vulns)
    else:
        print (
            "Protocol {} is not supported by this tool!".format(
                tester.test_params.protocol
            )
        )


if __name__ == "__main__":
    main(sys.argv[1:])
