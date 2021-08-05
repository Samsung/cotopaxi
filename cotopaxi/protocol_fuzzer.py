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
import random
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


def load_corpus(tester, corpus_dir_path):
    """Provide corpus of payloads based on options provided by args."""

    test_params = tester.test_params
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
    print_verbose(test_params, "corpus_dir: {}".format(corpus_dir_path))
    print_verbose(test_params, "Loaded corpus of {} testcases".format(len(testcases)))
    return testcases


def mutate_testcase(filename, content, mutation_nr, mutation_index, mutation_data):
    """Mutate single testcase."""

    mutation_nr = mutation_nr % 5
    if len(content) == 0:
        content = bytes(
            mutation_data,
        )
    mutation_index = mutation_index % len(content)
    mutation_data = mutation_data % 255
    filename_split = filename.split(".")
    # 0 - remove single byte (index given by mutation_index)
    # 1 - cut content after mutation index
    # 2 - change character at mutation_index to mutation data
    # 3 - insert character mutation data at mutation_index
    # 4 - duplicate character at mutation_index
    if mutation_nr == 0:
        mutation_description = "_rem_" + str(mutation_index)
        new_content = content[:mutation_index] + content[mutation_index + 1 :]
    elif mutation_nr == 1:
        mutation_description = "_cut_" + str(mutation_index)
        new_content = content[:mutation_index]
    elif mutation_nr == 2:
        mutation_description = "_flip_" + str(mutation_index)
        new_content = (
            content[:mutation_index]
            + bytes(
                mutation_data,
            )
            + content[mutation_index + 1 :]
        )
    elif mutation_nr == 3:
        mutation_description = "_ins_" + str(mutation_index)
        new_content = (
            content[:mutation_index]
            + bytes(
                mutation_data,
            )
            + content[mutation_index:]
        )
    else:
        mutation_description = "_dup_" + str(mutation_index)
        new_content = (
            content[:mutation_index]
            + (content[mutation_index:mutation_index])
            + content[mutation_index:]
        )
    if len(new_content) == 0:
        new_content = bytes(
            mutation_data,
        )
    if len(filename_split) > 1:
        filename_split[-1] += mutation_description
    else:
        filename_split[0] += mutation_description
    return ".".join(filename_split), new_content


def mutate_testcases(testcases, new_corpus_dir):
    """Mutate set of testcases."""

    if not os.path.exists(new_corpus_dir):
        os.makedirs(new_corpus_dir)
    for testcase in testcases:
        with open(testcase.payload_file, "rb") as file_handle:
            testcase_payload = file_handle.read()
        _, original_filename = os.path.split(testcase.payload_file)
        new_filename, new_content = mutate_testcase(
            original_filename,
            testcase_payload,
            random.randint(0, 5),
            random.randint(0, 9223372036854775807),
            random.randint(0, 255),
        )
        if len(new_filename) > 60:
            new_filename = new_filename[:20] + "___" + new_filename[40:]
        with open(os.path.join(new_corpus_dir, new_filename), "wb") as file:
            file.write(new_content)


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

    tester.argparser.add_argument(
        "--fuzzing-iterations",
        "-FI",
        action="store",
        type=int,
        default=0,
        help="number fuzzing iterations (mutations of corpus)",
    )

    options = tester.parse_args(args)
    if options.corpus_dir:
        corpus_dir_path = options.corpus_dir
        corpus_dir_base = options.corpus_dir + "_"
    else:
        corpus_dir_path = os.path.dirname(__file__) + "/fuzzing_corpus/"
        if tester.test_params.protocol.name != "ALL":
            corpus_dir_path += tester.test_params.protocol.name.lower()
        corpus_dir_base = os.getcwd() + "/fuzzing_corpus_"
    testcases = load_corpus(tester, corpus_dir_path)
    tester.perform_testing("protocol fuzzing", perform_protocol_fuzzing, testcases)

    max_iteration_len = len(str(options.fuzzing_iterations))
    for i in range(options.fuzzing_iterations):
        print(
            prepare_separator(
                "#", post_separator_text="\n\t\tStarting round {}\n".format(i + 2)
            )
        )
        str_i = str(i)
        corpus_new_dir = (
            corpus_dir_base + "0" * (max_iteration_len - len(str_i)) + str_i
        )
        mutate_testcases(testcases, corpus_new_dir)
        testcases = load_corpus(tester, corpus_new_dir)
        tester.perform_testing("protocol fuzzing", perform_protocol_fuzzing, testcases)


if __name__ == "__main__":
    main(sys.argv[1:])
