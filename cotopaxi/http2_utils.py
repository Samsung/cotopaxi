# -*- coding: utf-8 -*-
"""Set of common utils for HTTP/2 protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
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
import socket
from scapy.all import Raw
from scapy.contrib.http2 import H2Seq as HTTP2Message, H2PingFrame

from .common_utils import print_verbose, tcp_sr1
from .protocol_tester import TCPBasedProtocolTester

H2_CLIENT_CONNECTION_PREFACE = codecs.decode(
    "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a", "hex"
)


def build_http2_ping():
    """Create HTTP/2 ping based on provided data."""
    http2_request = HTTP2Message()
    http2_request.frames = [H2PingFrame()]
    return http2_request


class HTTP2Tester(TCPBasedProtocolTester):
    """Tester of HTTP/2 protocol."""

    def __init__(self):
        """Create empty HTTP2Tester."""
        TCPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "HTTP2"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Hypertext Transfer Protocol version 2"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 80

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return HTTP2Message

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return HTTP2Message

    @staticmethod
    def ping(test_params, show_result=False):
        """Check HTTP/2 service availability by sending GET message and waiting for response."""
        if not test_params:
            return None
        try:
            for _ in range(1 + test_params.nr_retries):
                in_data = tcp_sr1(test_params, bytes(H2_CLIENT_CONNECTION_PREFACE))
                if in_data:
                    print_verbose(
                        test_params,
                        "\n".join(
                            ["Received response:", 50 * "=", str(in_data), 50 * "="]
                        ),
                    )
                    http2_resp = HTTP2Message(in_data)
                    if http2_resp:
                        print_verbose(
                            test_params,
                            "[.] Parsed {} frames of HTTP/2 ".format(
                                len(http2_resp.frames)
                            ),
                        )
                        if test_params.verbose and Raw not in http2_resp:
                            http2_resp.show()
                        if len(http2_resp.frames) > 0 and Raw not in http2_resp:
                            return True

        except (socket.timeout, socket.error) as error:
            print_verbose(test_params, error)
        return False
