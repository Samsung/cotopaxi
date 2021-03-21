# -*- coding: utf-8 -*-
"""Tool for fingerprinting of network service at given IP and port ranges."""
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
import sys

from .coap_utils import CoAPTester, coap_sr1_file
from .common_utils import Protocol, print_verbose, SCAPY_SSL_TLS_NOT_INSTALLED
from .cotopaxi_tester import CotopaxiTester, protocol_enabled


RESULT_UNKNOWN = "Unknown"


def coap_classifier_level_2(test_results):
    """Classifier created as import of WEKA J48 tree (level 2)."""
    classification_result = RESULT_UNKNOWN
    if test_results[3].type == "No":
        if test_results[10].type == "No":
            if test_results[1].options == "Content-Format_Empty":
                classification_result = "smcp"
            if test_results[1].options == "ETag":
                classification_result = "libcoap"
        if test_results[10].type == "RST":
            classification_result = "FreeCoAP"
        if test_results[10].type == "ACK":
            classification_result = "moongoose"
    elif test_results[3].type == "Empty":
        classification_result = "iotivity"
    elif test_results[3].type == "ACK":
        if test_results[0].type == "No":
            classification_result = "coap-rs"
        elif test_results[0].type == "ACK":
            classification_result = "wakaama"
    return classification_result


def coap_classifier(test_results):
    """Classifier created as import of WEKA J48 tree."""
    classification_result = RESULT_UNKNOWN
    if test_results[1].type == "No":
        classification_result = coap_classifier_level_2(test_results)
    elif test_results[1].type == "RST":
        if test_results[9].code == "No":
            classification_result = "aiocoap"
        elif test_results[9].code == "Empty":
            classification_result = "ecoap"
        elif test_results[9].code == "4_00":
            classification_result = "CoAPthon"
    elif test_results[1].type == "ACK":
        classification_result = "microcoap"
    return classification_result


def dtls_classifier(test_results):
    """Classifier created as import of WEKA J48 tree."""
    # packet_4_version = no_response
    # | packet_9_description = empty: openssl(10.0)
    # | packet_9_description = protocol_version: libressl(10.0)
    # | packet_9_description = handshake_failure: tinydtls(10.0)
    # packet_4_version = empty: matrix(10.0)
    # packet_4_version = DTLS_1_0: gnutls(10.0)
    # packet_4_version = DTLS_1_1
    # | packet_8_version = no_response: goldy(10.0)
    # | packet_8_version = DTLS_1_1: mbed(10.0)
    classification_result = RESULT_UNKNOWN
    if test_results[4].version == "no_response":
        if test_results[9].description == "empty":
            classification_result = "openssl"
        elif test_results[9].description == "protocol_version":
            classification_result = "libressl"
        elif test_results[9].description == "handshake_failure":
            classification_result = "tinydtls"
    elif test_results[4].version == "empty":
        classification_result = "matrix"
    elif test_results[4].version == "DTLS_1_0":
        classification_result = "gnutls"
    elif test_results[4].version == "DTLS_1_1":
        if test_results[8].version == "no_response":
            classification_result = "mbed TLS (~2.4)"
        elif test_results[8].version == "DTLS_1_1":
            classification_result = "mbed TLS (~2.16)"
    return classification_result


def get_result_string(value):
    """Convert result value into string."""
    return "alive" if value else "dead"


def coap_fingerprint(test_params):
    """Fingerprinting of server for CoAP protocol."""
    coap_vuln_file_format = (
        os.path.dirname(__file__)
        + "/fingerprinting/coap/coap_finger_000_packet_{:03}.raw"
    )
    prev_verbose = test_params.verbose
    test_params.verbose = False
    alive_before = CoAPTester.ping(test_params)
    result = get_result_string(alive_before)
    print(
        "[.] Host {}:{} is {} before test!".format(
            test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port, result
        )
    )
    if not alive_before and not test_params.ignore_ping_check:
        print(
            "[.] CoAP fingerprinting stopped for {}:{} because server is not responding\n"
            "    (use --ignore-ping-check if you want to continue anyway)!".format(
                test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
            )
        )
        test_params.test_stats.inactive_endpoints[Protocol.DTLS].append(
            "{}:{}".format(
                test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
            )
        )
        return
    test_params.verbose = prev_verbose
    print_verbose(
        test_params,
        "Started fingerprinting of CoAP server {}:{}".format(
            test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
        ),
    )

    test_results = 12 * [None]
    test_packets = [0, 1, 3, 9, 10, 11]
    for i in test_packets:
        test_results[i] = coap_sr1_file(test_params, coap_vuln_file_format.format(i))
    test_params.verbose = prev_verbose
    alive_after = CoAPTester.ping(test_params)
    result = get_result_string(alive_after)

    print(
        "[.] Host {}:{} is {} after test!".format(
            test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port, result
        )
    )
    if prev_verbose:
        print("\nResults of fingerprinting:")
        for idx, result in enumerate(test_results):
            print("{0:02d} {1}".format(idx, str(result)))

    classification_result = coap_classifier(test_results)

    addr_port_result = "{}:{} is using {}".format(
        test_params.dst_endpoint.ip_addr,
        test_params.dst_endpoint.port,
        classification_result,
    )
    if classification_result != RESULT_UNKNOWN:
        test_params.test_stats.active_endpoints[Protocol.CoAP].append(addr_port_result)
    else:
        test_params.test_stats.potential_endpoints[Protocol.CoAP].append(
            "{}:{}".format(
                test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
            )
        )
    print(addr_port_result)


def service_fingerprint(test_params, test_cases):
    """Check service availability by sending 'ping' packet and waiting for response."""
    if protocol_enabled(Protocol.CoAP, test_params.protocol):
        coap_fingerprint(test_params)
    if protocol_enabled(Protocol.DTLS, test_params.protocol):
        try:
            from .dtls_utils import dtls_fingerprint

            dtls_fingerprint(test_params)
        except (ImportError, ModuleNotFound):
            print(SCAPY_SSL_TLS_NOT_INSTALLED)


def main(args):
    """Start server fingerprinting based on command line parameters."""
    tester = CotopaxiTester(
        check_ignore_ping=True,
        show_disclaimer=False,
        test_name="fingerprinting",
        use_generic_proto=False,
    )
    tester.test_params.positive_result_name = "Identified"
    tester.test_params.potential_result_name = "Unidentified endpoints"
    tester.parse_args(args)
    tester.perform_testing("service fingerprinting", service_fingerprint)


if __name__ == "__main__":
    main(sys.argv[1:])
