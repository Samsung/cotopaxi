# -*- coding: utf-8 -*-
"""Set of common utils for KNX protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
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

import socket
import struct

from .common_utils import print_verbose, tcp_sr1
from .protocol_tester import TCPBasedProtocolTester

KNX_CONNECT_MESSAGE = b"\x00\x05\x00&\x00\x00\x00"
KNX_CONN_RESP_MESSAGE = b"\x00\x02\x00&"


class KNXTester(TCPBasedProtocolTester):
    """Tester of KNX protocol."""

    def __init__(self):
        """Create empty KNXTester object."""
        TCPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "KNX"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "KoNneX protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 6720

    @staticmethod
    def ping(test_params, show_result=False):
        """Check KNX service availability by sending CONNECT message and waiting for response."""
        if not test_params:
            return None
        try:
            for _ in range(1 + test_params.nr_retries):
                for test_message in [KNX_CONNECT_MESSAGE]:
                    in_data = tcp_sr1(test_params, test_message)
                    if in_data:
                        if len(in_data) >= 4:
                            telegram_length = struct.unpack(">H", in_data[:2])[0]
                            telegram_type = struct.unpack(">H", in_data[-2:])[0]
                            print_verbose(
                                test_params, "telegram_length: " + str(telegram_length)
                            )
                            print_verbose(
                                test_params, "telegram_type: " + str(telegram_type)
                            )
                        else:
                            telegram_length = telegram_type = -1

                        str_in_data = str(in_data)
                        print_verbose(
                            test_params,
                            "\n".join(
                                [
                                    "Received response:",
                                    50 * "=",
                                    str_in_data.strip(),
                                    50 * "=",
                                ]
                            ),
                        )
                        if (
                            len(in_data) == 4
                            and telegram_length == 2
                            and telegram_type == 38
                        ):
                            print_verbose(test_params, "KNX CONNECT : SUCCESS")
                            return True
                        print_verbose(
                            test_params,
                            "[-] Response received, but not recognized as KNX message!",
                        )
        except (socket.timeout, socket.error) as error:
            print_verbose(test_params, error)
        return False
