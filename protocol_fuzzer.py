# -*- coding: utf-8 -*-
"""Tool for protocol fuzzing of network service at given IP and port ranges."""
#
#    Copyright (C) 2019 Samsung Electronics. All Rights Reserved.
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

import os
import sys
import time
from scapy.all import Raw
from scapy.contrib.coap import CoAP
from .common_utils import CotopaxiTester, print_verbose, sr1_file
from .service_ping import service_ping
from .vulnerability_tester import Vulnerability


class FuzzingCase(Vulnerability):
    """Object representing crash vulnerability."""

    def __init__(self, payload_file):
        Vulnerability.__init__(self, "", "", payload_file, "", "")

    def test_payload(self, test_params, test_timeouts, alive_before=True):
        """Send payload for fuzzing."""
        if not alive_before:
            alive_before = service_ping(test_params)
            if not alive_before:
                print("[+] Server {}:{} is not responding before sending payload"
                      .format(test_params.dst_endpoint.ip_addr,
                              test_params.dst_endpoint.port))
            else:
                print_verbose(test_params, "[+] Server {}:{} is alive before sending payload"
                              .format(test_params.dst_endpoint.ip_addr,
                                      test_params.dst_endpoint.port))
        if not alive_before and not test_params.ignore_ping_check:
            print("[.] Fuzzing stopped for {}:{} because server is not responding\n"
                  "    (use --ignore-ping-check if you want to continue anyway)!"
                  .format(test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port))
            return False
        print_verbose(test_params, 60*"-" + "\nRequest:")
        payload_sent_time = time.time()
        test_result = sr1_file(test_params, self.payload_file, test_params.verbose)
        print_verbose(test_params, 60 * "-")
        print("[.] Payload {} sent".format(self.payload_file))
        if test_result is not None:
            test_timeouts.append((time.time()-payload_sent_time, self.payload_file, test_result))
            print(60 * "-" + "\nResponse:")
            try:
                CoAP(test_result[Raw].load).show()
                print(60 * "-")
            except TypeError:
                print(60 * "-")
        else:
            print("Received no response from server")
            print(60 * "-")
        alive_after = service_ping(test_params)
        if not alive_after and alive_before:
            print("[+] Server {}:{} is dead after sending payload"
                  .format(test_params.dst_endpoint.ip_addr,
                          test_params.dst_endpoint.port))
            test_params.test_stats.active_endpoints[test_params.protocol].append(
                "{}:{} - payload: {}".format(test_params.dst_endpoint.ip_addr,
                                             test_params.dst_endpoint.port, self.payload_file))
            print("Waiting {} seconds for the server to start again.".format(60))
            time.sleep(60)
            if not service_ping(test_params):
                print("Server did not respawn (wait 1)!")
                time.sleep(60)
                if not service_ping(test_params):
                    print("Server did not respawn (wait 2)!\nExiting!")
                    return False
                else:
                    print("Server is alive again (after 2 waits)!")
        if alive_after:
            print_verbose(test_params, "[+] Server {}:{} is alive after sending payload {}"
                          .format(test_params.dst_endpoint.ip_addr,
                                  test_params.dst_endpoint.port,
                                  self.payload_file))
        print_verbose(test_params, "[+] Finished fuzzing with payload: {}"
                      .format(self.payload_file))
        print_verbose(test_params, 60 * "=")
        return True


def perform_protocol_fuzzing(test_params, test_cases):
    """Checks service availability by sending 'ping' packet and waiting for response."""
    test_timeouts = []
    alive = False
    test_cases.sort(key=lambda x: x.payload_file)
    for num, fuzzing_case in enumerate(test_cases, start=1):
        print_verbose(test_params, "[+] Started fuzzing payload (nr: {}): {}"
                      .format(num, fuzzing_case.payload_file))
        alive = fuzzing_case.test_payload(test_params, test_timeouts, alive)
        if not alive:
            return

    if test_timeouts:
        test_timeouts.sort(key=lambda x: x[0], reverse=True)
        print(80 * "-")
        print("\nPayloads with longest Round-Trip Time (RTT):")
        print(" RTT (sec) | Payload\n" + 80 * "-")
        for index in range(min(len(test_timeouts), len(test_cases)/10)):
            print("  {:0.5f}  | {}".format(test_timeouts[index][0], test_timeouts[index][1]))
        print(80 * "-")


def main(args):
    """Starts protocol fuzzer based on command line parameters"""

    tester = CotopaxiTester(check_ignore_ping=True, use_generic_proto=False)
    tester.test_params.positive_result_name = "Payloads causing crash"
    tester.test_params.potential_result_name = None
    tester.test_params.negative_result_name = None
    tester.argparser.add_argument('--corpus-dir', '-C', action='store', type=str,
                                  help="path to directory with fuzzing payloads (corpus)"
                                       " (each payload in separated file)")

    tester.argparser.add_argument('--delay-after-crash', '-DAC', action='store', type=str,
                                  help="path to directory with fuzzing payloads (corpus)"
                                       " (each payload in separated file)")
    options = tester.parse_args(args)
    test_params = tester.get_test_params()

    print_verbose(test_params, "corpus_dir: {}".format(options.corpus_dir))
    if options.corpus_dir:
        corpus_dir_path = options.corpus_dir
    else:
        corpus_dir_path = "cotopaxi/fuzzing_corpus/" + test_params.protocol.name.lower()
    print_verbose(test_params, 80 * "=")
    testcases = []
    for root, _, files in os.walk(corpus_dir_path):
        for file_name in files:
            testcases.append(FuzzingCase(os.path.join(root, file_name)))

    tester.perform_testing("protocol fuzzing", perform_protocol_fuzzing, testcases)


if __name__ == "__main__":
    main(sys.argv[1:])
