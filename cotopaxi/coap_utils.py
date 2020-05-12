# -*- coding: utf-8 -*-
"""Set of common utils for CoAP protocol handling."""
#
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz (Samsung R&D Poland),
#                Michał Radwański (Samsung R&D Poland)
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

import random
import sys

from hexdump import dehex
from scapy.all import IP, UDP
from scapy.contrib.coap import CoAP  # , coap_codes

from .common_utils import amplification_factor, print_verbose, show_verbose, udp_sr1
from .protocol_tester import ProtocolTester

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

COAP_PING_1_RAW = "40000001"
COAP_PING_2_RAW = "420184a77675b56261736963"

COAP_REV_CODES = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4}


def coap_scrap_response(resp_packet):
    """Parse response packet and scraps CoAP response from stdout."""
    parsed_response = ""
    if resp_packet.haslayer(IP):
        del resp_packet[IP].chksum
        del resp_packet[IP].id
    if resp_packet.haslayer(UDP):
        del resp_packet[UDP].chksum
        save_stdout, sys.stdout = sys.stdout, StringIO()
        coap = CoAP(resp_packet[UDP].load)
        coap.show()
        sys.stdout, save_stdout = save_stdout, sys.stdout
        parsed_response = save_stdout.getvalue()
    return parsed_response


def coap_check_url(test_params, method, url):
    """Check on CoAP server whether resource named url is available."""
    packet = CoAP()
    # 1 - GET
    # 2 - POST
    # 3 - PUT
    # 4 - DELETE
    if method in COAP_REV_CODES:
        packet[CoAP].code = COAP_REV_CODES[method]
    else:
        packet[CoAP].code = 1  # GET
    packet[CoAP].msg_id = random.randint(0, 32768)
    packet[CoAP].options = [("Uri-Path", url)]

    print_verbose(test_params, "\n" + 30 * "-" + "Request:\n")
    show_verbose(test_params, packet)
    print_verbose(test_params, "\n" + 30 * "-" + "\n")

    answer = udp_sr1(test_params, bytes(packet))

    if answer is not None:
        parsed_response = coap_scrap_response(answer)
        code = coap_convert_code(parsed_response)
        print_verbose(test_params, "\n" + 30 * "-" + "Response:\n")
        show_verbose(test_params, answer)
        print_verbose(test_params, parsed_response)

        if code != "Empty":
            print (
                "SENT size:{} RECV size:{} AMPLIFICATION FACTOR:{:0.2f}%".format(
                    len(packet),
                    len(answer),
                    amplification_factor(len(packet), len(answer)),
                )
            )
            return code
    else:
        print_verbose(test_params, "\n" + 30 * "-" + "\n No response\n")

    print_verbose(test_params, "\n" + 30 * "-" + "\n")
    return None


def coap_convert_type(response):
    """Convert CoAP server response to attribute type used by classifier."""
    types = {"ACK", "RST", "CON", "NON"}
    for type_in in types:
        if "type      = " + type_in in response:
            return type_in
    return "Empty"


def coap_convert_code(response):
    """Convert CoAP server response to attribute code used by classifier."""
    if "2.05 Content" in response:
        return "2_05"
    if "4.00 Bad Request" in response:
        return "4_00"
    if "4.01 Unauthorized" in response:
        return "4_01"
    if "4.04 Not Found" in response:
        return "4_04"
    if "4.05 Method Not Allowed" in response:
        return "4_05"
    return "Empty"


def coap_convert_options(response):
    """Convert CoAP server response to attribute options used by classifier."""
    return_response = "Empty"
    if "[('ETag'" in response:
        return_response = "ETag"
    if "[('Uri-Query', 'OK')]" in response:
        return_response = "Uri-Query_OK"
    if "[('Content-Format', '')]" in response:
        return_response = "Content-Format_Empty"
    if "[('Uri-Query', 'Unsupported cri')" in response:
        return_response = "Uri-Query_Unsupported_cri"
    if "[('Uri-Query', 'CoAP version mu')" in response:
        return_response = "Uri-Query_CoAP_version_mu"
    if "[('Content-Format', '\xff\xff')]" in response:
        return_response = "Content-Format_FFFF"
    if "[('Uri-Query', 'Method Not Allo')" in response:
        return_response = "Uri-Query_Method_Not_Allo"
    return return_response


class CoAPResults(object):
    """Wrapper for all CoAP results."""

    def __init__(self):
        """Create empty COAPResult object."""
        self.type = "No"
        self.code = "No"
        self.options = "No"

    def __str__(self):
        """Convert COAPResult object into str."""
        return "type = {} code = {} options = {}".format(
            self.type, self.code, self.options
        )

    def fill(self, type_name, code, options):
        """Fill object."""
        self.type = type_name
        self.code = code
        self.options = options


def coap_sr1(test_params, coap_test):
    """Send CoAP test message to server and parses response."""
    response = udp_sr1(test_params, coap_test)
    test_result = CoAPResults()
    if response is not None:
        resp_packet = response[0]
        parsed_response = coap_scrap_response(resp_packet)
        test_result.type = coap_convert_type(parsed_response)
        test_result.code = coap_convert_code(parsed_response)
        test_result.options = coap_convert_options(parsed_response)
        print_verbose(test_params, parsed_response)
    return test_result


def coap_sr1_file(test_params, test_filename):
    """Read CoAP test message from given file, sends this message to server and parses response."""
    with open(test_filename, "rb") as file_handle:
        coap_test = file_handle.read()
    return coap_sr1(test_params, coap_test)


class CoAPTester(ProtocolTester):
    """Tester of CoAP protocol."""

    def __init__(self):
        """Create empty CoAPTester object."""
        ProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "CoAP"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Constrained Application Protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 5683

    @staticmethod
    def transport_protocol():
        """Provide Scapy class of transport protocol used by this tester (usually TCP or UDP)."""
        return UDP

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return CoAP

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return CoAP

    @staticmethod
    def implements_service_ping():
        """Return True if this tester implements service_ping for this protocol."""
        return True

    @staticmethod
    def ping(test_params, show_result=False):
        """Check CoAP service availability by sending ping packet and waiting for response."""
        if not test_params:
            return None
        coap_ping_packets = [COAP_PING_1_RAW, COAP_PING_2_RAW]
        for coap_ping_raw in coap_ping_packets:
            packet_raw = dehex(coap_ping_raw)
            response = udp_sr1(test_params, packet_raw, test_params.wrap_secure_layer)
            if response is not None:
                for response_packet in response:
                    coap_response = coap_scrap_response(response_packet)
                    print_verbose(test_params, coap_response)
                    if (
                        "ver       = 1" in coap_response
                        and coap_convert_type(coap_response) != "Empty"
                    ):
                        return True
        return False

    @staticmethod
    def implements_fingerprinting():
        """Return True if this tester implements fingerprinting for this protocol."""
        return True

    @staticmethod
    def implements_resource_listing():
        """Return True if this tester implements resource for this protocol."""
        return True

    @staticmethod
    def implements_server_fuzzing():
        """Return True if this tester implements server fuzzing for this protocol."""
        return True

    @staticmethod
    def implements_client_fuzzing():
        """Return True if this tester implements clients fuzzing for this protocol."""
        return True

    @staticmethod
    def implements_vulnerability_testing():
        """Return True if this tester implements vulnerability testing for this protocol."""
        return True
