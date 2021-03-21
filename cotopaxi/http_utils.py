# -*- coding: utf-8 -*-
"""Set of common utils for HTTP protocol handling."""
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

import socket
from scapy.layers.http import HTTPRequest, HTTPResponse

from .common_utils import print_verbose, tcp_sr1
from .protocol_tester import TCPBasedProtocolTester

HTTP_REQUEST = "{} http://{} HTTP/1.1\r\n" "Host: {}:{}\r\n"


def build_http_query(test_params, method="GET", path="", data=None):
    """Create HTTP query string based on provided data."""
    http_query = HTTP_REQUEST.format(
        method, path, test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
    )
    if data:
        http_query += "Content-Length: {}\r\n".format(len(data))
        http_query += data + "\r\n"
    return http_query + "\r\n"


class HTTPTester(TCPBasedProtocolTester):
    """Tester of HTTP protocol."""

    def __init__(self):
        """Create empty HTTPTester."""
        TCPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "HTTP"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Hypertext Transfer Protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 80

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return HTTPRequest

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return HTTPResponse

    @staticmethod
    def ping(test_params, show_result=False):
        """Check HTTP service availability by sending GET message and waiting for response."""
        if not test_params:
            return None
        try:
            for _ in range(1 + test_params.nr_retries):
                in_data = str(tcp_sr1(test_params, build_http_query(test_params)))
                if in_data:
                    print_verbose(
                        test_params,
                        "\n".join(["Received response:", 50 * "=", in_data, 50 * "="]),
                    )
                    if "HTTP/" in in_data:
                        print_verbose(test_params, "HTTP GET : SUCCESS")
                        return True
        except (socket.timeout, socket.error) as error:
            print_verbose(test_params, error)
        return False
