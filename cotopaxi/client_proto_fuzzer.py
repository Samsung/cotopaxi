# -*- coding: utf-8 -*-
"""Tool for protocol fuzzing of network clients."""
#
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Author: Jakub Botwicz (Samsung R&D Poland)
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


def tcp_server(test_params, payloads):
    """Start TCP server used for testing clients."""
    print (
        "Starting TCP server on IP {} port {}".format(
            test_params.src_endpoint.ip_addr, test_params.src_endpoint.port
        )
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((test_params.src_endpoint.ip_addr, test_params.src_endpoint.port))
    sock.listen(10)

    try:
        for payload in payloads:
            # print_verbose(test_params, "Next payload is: {}".format(payload.payload_file))
            with open(payload.payload_file, "rb") as file_handle:
                message = file_handle.read()
            (client_sock, addr) = sock.accept()
            test_params.test_stats.packets_received += 1
            print_verbose(test_params, "Received packet from: {}".format(addr))
            client_sock.send(message)
            client_sock.close()
            test_params.test_stats.packets_sent += 1
            if payload.name:
                if payload.cve_id:
                    print (
                        "Payload for vulnerability {} / {} sent.".format(
                            payload.name, payload.cve_id
                        )
                    )
                else:
                    print ("Payload for vulnerability {} sent.".format(payload.name))
            else:
                print ("Payload {} sent!".format(payload.payload_file))
        print ("[.] Finished {} (all payloads sent).".format(test_params.test_name))
    except KeyboardInterrupt:
        print ("\nExiting...")
    finally:
        test_params.print_client_stats()


def udp_server(test_params, payloads):
    """Start UDP server used for testing clients."""
    print (
        "Starting UDP server on IP {} port {}".format(
            test_params.src_endpoint.ip_addr, test_params.src_endpoint.port
        )
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((test_params.src_endpoint.ip_addr, test_params.src_endpoint.port))

    try:
        for payload in payloads:
            # print_verbose(test_params, "Next payload is: {}".format(payload.payload_file))
            with open(payload.payload_file, "rb") as payload_file:
                message = payload_file.read()
            (_, addr) = sock.recvfrom(INPUT_BUFFER_SIZE)
            test_params.test_stats.packets_received += 1
            print_verbose(test_params, "Received packet from: {}".format(addr))
            sock.sendto(message, addr)
            test_params.test_stats.packets_sent += 1
            if payload.name:
                if payload.cve_id:
                    print (
                        "Payload for vulnerability {} / {} sent.".format(
                            payload.name, payload.cve_id
                        )
                    )
                else:
                    print ("Payload for vulnerability {} sent.".format(payload.name))
            else:
                print ("Payload {} sent!".format(payload.payload_file))
        print ("[.] Finished {} (all payloads sent).".format(test_params.test_name))
    except KeyboardInterrupt:
        print ("\nExiting...")
    finally:
        test_params.print_client_stats()


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

    print ("Loaded {} payloads for fuzzing".format(len(testcases)))

    if tester.test_params.protocol in protocols_using(UDP):
        udp_server(tester.test_params, testcases)
    elif tester.test_params.protocol in protocols_using(TCP):
        tcp_server(tester.test_params, testcases)
    else:
        print (
            "Protocol {} is not supported by this tool!".format(
                tester.test_params.protocol
            )
        )


if __name__ == "__main__":
    main(sys.argv[1:])
