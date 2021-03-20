# -*- coding: utf-8 -*-
"""Tool for protocol fuzzing of network clients."""
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
import sys
from scapy.all import TCP, UDP

from .common_utils import INPUT_BUFFER_SIZE, print_verbose
from .cotopaxi_tester import CotopaxiClientTester, protocols_using
from .protocol_fuzzer import load_corpus


class ClientFuzzer(object):
    """Generic fuzzer server used to perform fuzzing."""

    def __init__(self, test_params):
        """Initialize client fuzzer using given test_params."""
        self.test_params = test_params
        self.sock = None
        self.client_addr = None

    def start_server(self):
        """Start server used for testing clients."""
        print(
            "Starting server on IP {} port {}".format(
                self.test_params.src_endpoint.ip_addr,
                self.test_params.src_endpoint.port,
            )
        )

    def wait_client(self):
        """Wait for client."""
        pass

    def send_message(self, message):
        """Send message to client."""
        pass

    def perform_fuzzing(self, payloads):
        """Perform fuzzing using provided payloads."""
        self.start_server()
        try:
            for payload in payloads:
                self.wait_client()
                with open(payload.payload_file, "rb") as payload_file:
                    payload_content = payload_file.read()
                self.test_params.test_stats.packets_received += 1
                print_verbose(
                    self.test_params,
                    "Received packet from: {}".format(self.client_addr),
                )
                self.send_message(payload_content)
                self.test_params.test_stats.packets_sent += 1
                if payload.name:
                    if payload.cve_id:
                        print(
                            "Payload for vulnerability {} / {} sent.".format(
                                payload.name, payload.cve_id
                            )
                        )
                    else:
                        print("Payload for vulnerability {} sent.".format(payload.name))
                else:
                    print("Payload {} sent!".format(payload.payload_file))
            print(
                "[.] Finished {} (all payloads sent).".format(
                    self.test_params.test_name
                )
            )
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.test_params.print_client_stats()


class UDPFuzzer(ClientFuzzer):
    """UDP fuzzer server used to perform fuzzing."""

    def __init__(self, test_params):
        """Initialize client fuzzer using given test_params."""
        ClientFuzzer.__init__(self, test_params)

    def start_server(self):
        """Start server used for testing clients."""
        super(UDPFuzzer, self).start_server()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(
            (self.test_params.src_endpoint.ip_addr, self.test_params.src_endpoint.port)
        )

    def wait_client(self):
        """Wait for client."""
        (_, self.client_addr) = self.sock.recvfrom(INPUT_BUFFER_SIZE)

    def send_message(self, message):
        """Send message to client."""
        self.sock.sendto(message, self.client_addr)


class TCPFuzzer(ClientFuzzer):
    """TCP fuzzer server used to perform fuzzing."""

    def __init__(self, test_params):
        """Initialize client fuzzer using given test_params."""
        ClientFuzzer.__init__(self, test_params)
        self.client_sock = None

    def start_server(self):
        """Start server used for testing clients."""
        super(TCPFuzzer, self).start_server()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(
            (self.test_params.src_endpoint.ip_addr, self.test_params.src_endpoint.port)
        )
        self.sock.listen(10)

    def wait_client(self):
        """Wait for client."""
        (self.client_sock, self.client_addr) = self.sock.accept()

    def send_message(self, message):
        """Send message to client."""
        self.client_sock.send(message)
        self.client_sock.close()


def main(args):
    """Start client protocol fuzzer based on command line parameters."""
    tester = CotopaxiClientTester("client fuzzing")
    tester.argparser.add_argument(
        "--corpus-dir",
        "-C",
        action="store",
        type=str,
        help="path to directory with fuzzing payloads (corpus)"
        " (each payload in separated file)",
    )

    testcases = load_corpus(tester, args)
    print("Loaded {} payloads for fuzzing".format(len(testcases)))

    if tester.test_params.protocol in protocols_using(UDP):
        server = UDPFuzzer(tester.test_params)
        server.perform_fuzzing(testcases)
    elif tester.test_params.protocol in protocols_using(TCP):
        server = TCPFuzzer(tester.test_params)
        server.perform_fuzzing(testcases)
    else:
        print(
            "Protocol {} is not supported by this tool!".format(
                tester.test_params.protocol
            )
        )


if __name__ == "__main__":
    main(sys.argv[1:])
