# -*- coding: utf-8 -*-
"""Set of common utils for RTSP protocol handling."""
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
from random import randint

from .common_utils import print_verbose, tcp_sr1
from .http_utils import HTTPTester

RTSP_QUERY = "{} rtsp://{}:{}/{} RTSP/1.0\r\n" "CSeq:{}\r\n" "\r\n"


def build_rtsp_query(test_params, method="DESCRIBE", path="", cseq=None):
    """Create RTSP query string based on provided data."""
    if not cseq:
        cseq = randint(0, 10000)  # nosec
    return RTSP_QUERY.format(
        method,
        test_params.dst_endpoint.ip_addr,
        test_params.dst_endpoint.port,
        path,
        cseq,
    )


class RTSPTester(HTTPTester):
    """Tester of RTSP protocol."""

    def __init__(self):
        """Create empty RTSPTester object."""
        HTTPTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "RTSP"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Real Time Streaming Protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 554

    @staticmethod
    def ping(test_params, show_result=False):
        """Check RTSP service availability by sending DESCRIBE message and waiting for response."""
        if not test_params:
            return None
        rtsp_describe_message = build_rtsp_query(test_params, "DESCRIBE")
        rtsp_options_message = build_rtsp_query(test_params, "OPTIONS")
        try:
            for _ in range(1 + test_params.nr_retries):
                for test_message in [rtsp_options_message, rtsp_describe_message]:
                    in_data = tcp_sr1(test_params, test_message)
                    if in_data:
                        in_data = str(in_data)
                        print_verbose(
                            test_params,
                            "\n".join(
                                [
                                    "Received response:",
                                    50 * "=",
                                    in_data.strip(),
                                    50 * "=",
                                ]
                            ),
                        )
                        if "HTTP/1." in in_data and "400 Bad Request" in in_data:
                            print_verbose(test_params, "Tested server is HTTP server.")
                            return False
                        if "RTSP/1.0" in in_data:
                            print_verbose(test_params, "RTSP DESCRIBE : SUCCESS")
                            return True
        except (socket.timeout, socket.error) as error:
            print_verbose(test_params, error)
        return False

    @staticmethod
    def implements_resource_listing():
        """Return True if this tester implements resource for this protocol."""
        return True
