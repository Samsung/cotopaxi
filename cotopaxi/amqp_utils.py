# -*- coding: utf-8 -*-
"""Set of common utils for AMQP protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz
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

from .common_utils import print_verbose, tcp_sr1, prepare_separator
from .http_utils import HTTPTester

AMQP_PING_000 = "414d515001010009"


class AMQPTester(HTTPTester):
    """Tester of AMQP protocol."""

    def __init__(self):
        """Construct AMQPTester."""
        HTTPTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "AMQP"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Advanced Message Queuing Protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 5672

    @staticmethod
    def ping(test_params, show_result=False):
        """Check AMQP service availability by sending DESCRIBE message and waiting for response."""
        if not test_params:
            return None
        ping_packets = [codecs.decode(AMQP_PING_000, "hex")]
        try:
            for _ in range(1 + test_params.nr_retries):
                for test_message in ping_packets:
                    in_data = str(tcp_sr1(test_params, test_message))
                    if in_data:
                        print_verbose(
                            test_params,
                            "\n".join(
                                [
                                    "Received response:",
                                    prepare_separator(),
                                    in_data.strip(),
                                    prepare_separator(),
                                ]
                            ),
                        )
                        if "HTTP/1." in in_data and "400 Bad Request" in in_data:
                            print_verbose(test_params, "Tested server is HTTP server.")
                            return False
                        if (
                            "AMQP" in in_data
                            or "\x00\x0a\x00\x09" in in_data
                            and "capabilities" in in_data
                        ):
                            print_verbose(test_params, "AMQP Connection.Start: SUCCESS")
                            return True
        except (socket.timeout, socket.error) as error:
            print_verbose(test_params, error)
        return False
