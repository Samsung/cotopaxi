# -*- coding: utf-8 -*-
"""Tool for protocol fuzzing of network service at given IP and port ranges."""
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
import struct
import sys
import time

from scapy.all import Raw

from .common_utils import print_verbose, prepare_separator
from .cotopaxi_tester import CotopaxiTester, PROTOCOL_TESTERS, sr1_file
from .service_ping import service_ping
from .vulnerability_tester import Vulnerability


class FuzzingCase(Vulnerability):
    """Object representing crash vulnerability."""

    def __init__(self, payload_file):
        """Create empty FuzzingCase object."""
        Vulnerability.__init__(self, payload_file=payload_file)

    def verify(self, test_params):
        """Verify whether remote host is vulnerable to this vulnerability."""
        pass

    @staticmethod
    def wait_server_respawn(test_params, wait_time_sec=60, nr_iterations=2):
        """Wait for server to respawn after crash."""
        print("Waiting {} seconds for the server to start again.".format(wait_time_sec))
        iteration = 0
        server_respawned = False
        while not server_respawned and iteration < nr_iterations:
            time.sleep(wait_time_sec)
            if not service_ping(test_params):
                print("Server did not respawn (wait {})!".format(iteration + 1))
            else:
                print("Server is alive again (after {} waits)!".format(iteration + 1))
                return True
            iteration += 1
        print(
            "Server did not respawn after {} x {} sec!\nExiting!".format(
                nr_iterations, wait_time_sec
            )
        )
        return False

    def test_payload(self, test_params, test_timeouts, alive_before=True):
        """Send payload for fuzzing.

        test_timeouts list is extended if applicable.
        """
        if not alive_before:
            alive_before = service_ping(test_params)
            if not alive_before:
                print(
                    "[+] Server {}:{} is not responding before sending payload".format(
                        test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
                    )
                )
            else:
                print_verbose(
                    test_params,
                    "[+] Server {}:{} is alive before sending payload".format(
                        test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
                    ),
                )
        if not alive_before and not test_params.ignore_ping_check:
            print(
                "[.] Fuzzing stopped for {}:{} because server is not responding\n"
                "    (use --ignore-ping-check if you want to continue anyway)!".format(
                    test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
                )
            )
            return False
        print_verbose(
            test_params, prepare_separator("-", post_separator_text="Request:")
        )
        payload_sent_time = time.time()
        test_result = sr1_file(test_params, self.payload_file, test_params.verbose)
        print_verbose(test_params, prepare_separator("-"))
        print("[.] Payload {} sent".format(self.payload_file))
        if test_result is not None:
            test_timeouts.append(
                (time.time() - payload_sent_time, self.payload_file, test_result)
            )
            print(prepare_separator("-", post_separator_text="Response:"))
            try:
                proto_handler = PROTOCOL_TESTERS[test_params.protocol].response_parser()
                packet = proto_handler(test_result[Raw].load)
                packet.show()
            except (TypeError, IndexError, struct.error):
                pass
            print(prepare_separator("-"))
        else:
            print("Received no response from server")
            print(prepare_separator("-"))
        alive_after = service_ping(test_params)
        flag = True
        if not alive_after:
            alive_after = service_ping(test_params)
            flag = False
            if not alive_after and alive_before and not test_params.ignore_ping_check:
                print(
                    "[+] Server {}:{} is dead after sending payload".format(
                        test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
                    )
                )
                test_params.test_stats.active_endpoints[test_params.protocol].append(
                    "{}:{} - payload: {}".format(
                        test_params.dst_endpoint.ip_addr,
                        test_params.dst_endpoint.port,
                        self.payload_file,
                    )
                )
                if not self.wait_server_respawn(test_params):
                    return False
            else:
                flag = True
        if flag and alive_after and not test_params.ignore_ping_check:
            print_verbose(
                test_params,
                "[+] Server {}:{} is alive after sending payload {}".format(
                    test_params.dst_endpoint.ip_addr,
                    test_params.dst_endpoint.port,
                    self.payload_file,
                ),
            )
        print_verbose(
            test_params,
            "[+] Finished fuzzing with payload: {}".format(self.payload_file),
        )
        print_verbose(test_params, prepare_separator())
        return True


def perform_protocol_fuzzing(test_params, test_cases):
    """Check service availability by sending 'ping' packet and waiting for response."""
    test_timeouts = []
    alive = False
    test_cases.sort(key=lambda x: x.payload_file)
    for num, fuzzing_case in enumerate(test_cases, start=1):
        print_verbose(
            test_params,
            "[+] Started fuzzing payload (nr: {}): {}".format(
                num, fuzzing_case.payload_file
            ),
        )
        alive = fuzzing_case.test_payload(test_params, test_timeouts, alive)
        if not alive:
            return

    if test_timeouts:
        test_timeouts.sort(reverse=True)
        print(prepare_separator())
        print("\nPayloads with longest Round-Trip Time (RTT):")
        print(prepare_separator("-", pre_separator_text="RTT (sec) | Payload"))
        for _, timeout in zip(range(len(test_cases) // 10), test_timeouts):
            print("  {:0.5f}  | {}".format(timeout[0], timeout[1]))
        print(prepare_separator("-"))


def load_corpus(tester, args):
    """Provide corpus of payloads based on options provided by args."""
    options = tester.parse_args(args)
    test_params = tester.test_params

    print_verbose(test_params, "corpus_dir: {}".format(options.corpus_dir))
    if options.corpus_dir:
        corpus_dir_path = options.corpus_dir
    else:
        corpus_dir_path = os.path.dirname(__file__) + "/fuzzing_corpus/"
        if test_params.protocol.name != "ALL":
            corpus_dir_path += test_params.protocol.name.lower()
    print_verbose(test_params, prepare_separator())
    testcases = []
    for root, _, files in os.walk(corpus_dir_path):
        for file_name in files:
            testcases.append(FuzzingCase(os.path.join(root, file_name)))
    if not testcases:
        sys.exit(
            "Cannot load testcases from provided path: {}\n"
            "Testing stopped!".format(corpus_dir_path)
        )
    print_verbose(test_params, "Loaded corpus of {} testcases".format(len(testcases)))
    return testcases


def main(args):
    """Start protocol fuzzer based on command line parameters."""
    tester = CotopaxiTester(
        test_name="server fuzzing", check_ignore_ping=True, use_generic_proto=False
    )
    tester.test_params.positive_result_name = "Payloads causing crash"
    tester.test_params.potential_result_name = None
    tester.test_params.negative_result_name = None
    tester.argparser.add_argument(
        "--corpus-dir",
        "-C",
        action="store",
        type=str,
        help="path to directory with fuzzing payloads (corpus)"
        " (each payload in separated file)",
    )

    tester.argparser.add_argument(
        "--delay-after-crash",
        "-DAC",
        action="store",
        type=str,
        default="60",
        help="number of seconds that fuzzer will wait after crash"
        " for respawning tested server",
    )

    testcases = load_corpus(tester, args)

    tester.perform_testing("protocol fuzzing", perform_protocol_fuzzing, testcases)


if __name__ == "__main__":
    main(sys.argv[1:])
