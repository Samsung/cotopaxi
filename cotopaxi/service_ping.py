# -*- coding: utf-8 -*-
"""Tool for checking availability of network service."""
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

import socket
import sys

from .common_utils import print_verbose
from .cotopaxi_tester import CotopaxiTester, PROTOCOL_TESTERS, protocol_enabled


def endpoint_string(test_params):
    """Return endpoint description in form of string."""
    return "{}:{}".format(
        test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
    )


def service_ping(test_params, show_result=False):
    """Check service availability by sending 'ping' packet and waiting for response."""
    try:
        ping_result = ""
        for protocol in PROTOCOL_TESTERS:
            if (
                protocol_enabled(protocol, test_params.protocol)
                and PROTOCOL_TESTERS[protocol].implements_service_ping()
            ):
                if PROTOCOL_TESTERS[protocol].ping(test_params) is True:
                    ping_result = "responds"
                else:
                    ping_result = "does NOT respond"
                if show_result:
                    if ping_result == "responds":
                        endpoints = test_params.test_stats.active_endpoints
                    else:
                        endpoints = test_params.test_stats.inactive_endpoints
                    endpoints[protocol].append(endpoint_string(test_params))
                    print(
                        '[+] Host {}:{} {} to {} "protocol ping" message'.format(
                            test_params.dst_endpoint.ip_addr,
                            test_params.dst_endpoint.port,
                            ping_result,
                            PROTOCOL_TESTERS[protocol].protocol_short_name(),
                        )
                    )
        if ping_result == "responds":
            return True
    except socket.error as type_exception:
        print_verbose(test_params, "Type error: '{0}'.".format(type_exception))
        print(type_exception)

    return False


def perform_service_ping(test_params, test_cases):
    """Check service availability by sending 'ping' packet and waiting for response."""
    return service_ping(test_params, True)


def main(args):
    """Start service ping based on command line parameters."""
    tester = CotopaxiTester(test_name="service ping", show_disclaimer=False)
    tester.parse_args(args)
    tester.perform_testing("service ping", perform_service_ping)


if __name__ == "__main__":
    main(sys.argv[1:])
