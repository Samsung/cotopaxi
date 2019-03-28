# -*- coding: utf-8 -*-
"""Set of common utils for DTLS protocol handling."""
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

import sys
import socket
import struct
from scapy.all import ICMP, Raw, bind_layers
from scapy.layers.ssl_tls import DTLSRecord, TLS_VERSIONS, TLS_CONTENT_TYPES, \
    TLSDecryptablePacket, ByteEnumField, TLSAlertLevel, DTLSClientHello, \
    TLS_ALERT_LEVELS, TLS_ALERT_DESCRIPTIONS, TLSAlertDescription, TLSContentType, \
    DTLSHandshake, TLS_HANDSHAKE_TYPES
from IPy import IP as IPY_IP
from .common_utils import print_verbose, show_verbose, INPUT_BUFFER_SIZE, udp_sr1

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


def scrap_dtls_response(resp_packet):
    """Parses response packet and scraps DTLS response from stdout."""
    capture = StringIO()
    save_stdout = sys.stdout
    sys.stdout = capture
    resp_packet.show()
    sys.stdout = save_stdout
    parsed_response = capture.getvalue()
    parsed_response = "len(parsed_response): {}\n".format(len(parsed_response)) + parsed_response
    return parsed_response


class DTLSAlert(TLSDecryptablePacket):
    """Additional class for scapy support for DTLS"""
    name = "DTLS Alert"
    fields_desc = [ByteEnumField("level", TLSAlertLevel.WARNING, TLS_ALERT_LEVELS),
                   ByteEnumField("description", TLSAlertDescription.CLOSE_NOTIFY,
                                 TLS_ALERT_DESCRIPTIONS)]


bind_layers(DTLSRecord, DTLSAlert, {'content_type': TLSContentType.ALERT})


def show_dtls_packet(packet):
    """"Displays DTLS packet."""
    if packet.getlayer(Raw):
        dtls = DTLSRecord(packet[Raw].load)
        print(dtls)


# raw DTLS 1.0 Client Hello message
DTLS_PING = ('450000e63b1040004011e95d6a78b8116a788897e26b115c00d2167d16feff0000000000000'
             '00000bd010000b100000000000000b1feffbf00446ba28fda327463b4fcac60e7908e46920e046a4508'
             'b7623f89efc3ed2000000056c014c00a00390038003700360088008700860085c00fc00500350084c01'
             '3c0090033003200310030009a0099009800970045004400430042c00ec004002f00960041c012c00800'
             '1600130010000dc00dc003000a00ff01000031000b000403000102000a001c001a00170019001c001b0'
             '018001a0016000e000d000b000c0009000a00230000000f000101')

# 1 ciphersuite and no extensions
DTLS_1_0_HELLO_NMAP = "16feff000000000000000000360100002a000000000000002afefd000000007c77401e8"\
                      "ac822a0a018ff9308caac0a642fc92264bc08a81689193000000002002f0100"

# 13 ciphersuites and 104 bytes of extensions
DTLS_1_0_HELLO_BOTAN_CLIENT = "16feff000000000000000000b8010000ac00000000000000acfefd5c1e6c4479"\
                              "44afe889b2c6ca1fdf2f67a159adf4a0b2084eec762fd96247fec20000001a16"\
                              "b816b716ba16b9cca9cca8c02cc030c02bc02fccaa009f009e01000068000000"\
                              "0e000c0000096c6f63616c686f7374000500050100000000000a001a0018001d"\
                              "0017001a0018001b0019001c01000101010201030104000b00020100000d0014"\
                              "0012080508040806050106010401050306030403001600000017000000230000"\
                              "ff01000100"

# DTLS Record 1.0 Handshake DTLS 1.2, 28 ciphersuites, 23 signature
DTLS_1_2_HELLO_OPENSSL_CLIENT = "16feff000000000000000500dc010000d000000000000000d0fefdb96c6216"\
                                "16da19137a8a6b0405dfb2816a17eca8dda72b2e58f6b8227f592de4000000"\
                                "38c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067"\
                                "c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100006e00"\
                                "000012001000000d3139322e3136382e34332e3833000b000403000102000a"\
                                "000c000a001d0017001e00190018002300000016000000170000000d003000"\
                                "2e040305030603080708080809080a080b0804080508060401050106010303"\
                                "02030301020103020202040205020602"

DTLS_1_0_HELLO_COOKIE_MBED_CLIENT = ("16feff000000000000000101c4010001b800010000000001b8fefd5c1"
                                     "f6de04964434805887ba73f3757ede24f5f15fd3d8cd7edbcd7719554"
                                     "7a9200205c1f6de0a77d00d7c810669b65a6b8fb8ffbeab0358752e80"
                                     "4194b01e566ad340114cca8cca9ccaac02cc030009fc0adc09fc024c0"
                                     "28006bc00ac0140039c0afc0a3c087c08bc07dc073c07700c40088c02"
                                     "bc02f009ec0acc09ec023c0270067c009c0130033c0aec0a2c086c08a"
                                     "c07cc072c07600be0045c008c0120016ccacccad00abc0a7c03800b3c"
                                     "0360091c091c09bc097c0ab00aac0a6c03700b2c0350090c090c096c0"
                                     "9ac0aac034008f009dc09d003d0035c032c02ac00fc02ec026c005c0a"
                                     "1c07b00c00084c08dc079c089c075009cc09c003c002fc031c029c00e"
                                     "c02dc025c004c0a0c07a00ba0041c08cc078c088c074000ac00dc003c"
                                     "cae00ad00b70095c093c09900ac00b60094c092c0980093ccab00a9c0"
                                     "a500af008dc08fc095c0a900a8c0a400ae008cc08ec094c0a8008b00f"
                                     "f0100005a0000000e000c0000096c6f63616c686f7374000d00160014"
                                     "0603060105030501040304010303030102030201000a0018001600190"
                                     "01c0018001b00170016001a0015001400130012000b00020100001600"
                                     "000017000000230000")

DTLS_1_0_CLIENT_KEY_EXCHANGE_MBED_CLIENT = ("16fefd00000000000000020092100000860002000000000086"
                                            "850401123a128c31df316d63c7173cdd4c510032adf11359dd"
                                            "bcb6604ccebc8977cf416cfbb25eadb4d3e1bf64652505660d"
                                            "cd8160fd64c461b9cb7c2e5921654811094200cd0c610af469"
                                            "d4af8cfb01bbbde5777c1f8d9ace1fc9e24a9916b73a8e540e"
                                            "da223ad47beb28093d35e99690a294798ac98780f9aaa449c5"
                                            "12323e0f0f5a38b31414fefd000000000000000300010116fe"
                                            "fd0001000000000000002859e3345ab947356c7c45419ec4d5"
                                            "5f67428ce4d6817ba01af949fe6ce58da64305b4c8ac1be58993")

DTLS_1_0_CLIENT_APP_DATA_MBED_CLIENT = ("17fefd000100000000000100194d40f2faefbc6d7c84c52f4053fe"
                                        "cd0e0f6897637a464da099")

DTLS_1_0_CLIENT_ENCRYPTED_ALERT_MBED_CLIENT = ("15fefd00010000000000020012b425d3df55e0a0f580e701"
                                               "8ae483f05b69f5")

DTLS_1_0_CERT_FRAGMENT = ("16feff000000000000000300d70b00038400020000710000cb060355040b0c0444657"
                          "074310d300b06035504030c0474657374311c301a06092a864886f70d010901160d74"
                          "65737440746573742e636f6d301e170d3138313131383134323235305a170d3238313"
                          "131353134323235305a307f310b300906035504061302504c3114301206035504080c"
                          "0b4d617a6f776965636b6965310f300d06035504070c06576172736177310d300b060"
                          "355040a0c0454657374310d300b060355040b0c0444657074310d300b06035504030c"
                          "0474657374311c301a06092a864886f70d01090116")


def check_dtls_response(test_params, response):
    """Checks whether response is DTLS packet"""
    if response is not None and DTLSRecord in response:
        try:
            print_verbose(test_params, "Found packet protocol: {0} with content type: {1}"
                          .format(TLS_VERSIONS[response.version],
                                  TLS_CONTENT_TYPES[response.content_type]))
            if test_params.verbose:
                response.show()
            if response.version in TLS_VERSIONS and response.content_type in TLS_CONTENT_TYPES:
                if TLS_CONTENT_TYPES[response.content_type] == 'handshake':
                    print_verbose(test_params, "response[DTLSHandshake].type: {}"
                                  .format(TLS_HANDSHAKE_TYPES[response[DTLSHandshake].type]))
                    if TLS_HANDSHAKE_TYPES[response[DTLSHandshake].type] != "hello_verify_request":
                        print("[+] DTLS server does not respond with Hello Verify Request "
                              "(found message: {})- \n"
                              "so it can potentially be used to perform DDoS attacks!"
                              .format(TLS_HANDSHAKE_TYPES[response[DTLSHandshake].type]))
                return True
        except KeyError:
            pass
    return False


def udp_send(test_params, data):
    """Function to send data using UDP protocol"""
    dst_ip = IPY_IP(test_params.dst_endpoint.ip_addr)
    if dst_ip.version() == 4:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    elif dst_ip.version() == 6:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(test_params.timeout_sec)

    request_size = len(data)
    response_size = 0
    print_verbose(test_params, "src_ip: {} src_port: {} nr_retries: {}"
                  .format(test_params.src_endpoint.ip_addr,
                          test_params.src_endpoint.port,
                          test_params.nr_retries))

    sock.sendto(data, (test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port))

    in_data = None
    try:
        while True:
            in_data, server_addr = sock.recvfrom(INPUT_BUFFER_SIZE)
            response_size += len(in_data)
            print_verbose(test_params, "Received packet size {} from {}"
                          .format(len(in_data), server_addr))
            response = DTLSRecord(in_data)
            print_verbose(test_params, "Received packet DTLS type {}"
                          .format(response.content_type))
            show_verbose(test_params, response)
            return response
    except socket.timeout:
        print_verbose(test_params, "Timeout")
    except struct.error:
        print_verbose(test_params, "Parsing of DTLS message failed!")
    print_verbose(test_params, "Request size = {}".format(request_size))
    print_verbose(test_params, "Response size = {}".format(response_size))
    return in_data


def scrap_response(test_params, packet):
    """Scraps text description of DTLS packet"""
    try:
        while True:
            in_data = packet[Raw].load
            response = DTLSRecord(in_data)
            print_verbose(test_params, "Received packet DTLS type {}"
                          .format(response.content_type))
            show_verbose(test_params, response)
            return response
    except (struct.error, TypeError, IndexError):
        print_verbose(test_params, "Parsing of DTLS message failed!")
    return None


def dtls_ping(test_params):
    """Checks DTLS service availability by sending ping packet and waiting for response."""

    ping_packets = [DTLS_1_0_HELLO_NMAP, DTLS_1_0_HELLO_BOTAN_CLIENT, DTLS_1_2_HELLO_OPENSSL_CLIENT]

    for ping_packet in ping_packets:
        ping_data = ping_packet.decode('hex')

        response = udp_sr1(test_params, ping_data)
        if not response:
            continue
        if ICMP in response and response[ICMP].type == 3:
            print_verbose(test_params, "Received ICMP dest-unreachable")
            continue
        parsed_response = scrap_response(test_params, response)
        if check_dtls_response(test_params, parsed_response):
            return True

    return False


def prepare_dtls_test_packets():
    """Prepares list of packets to perform server fingerprinting."""
    test_packets = [DTLS_1_0_CLIENT_KEY_EXCHANGE_MBED_CLIENT, DTLS_1_0_CLIENT_APP_DATA_MBED_CLIENT,
                    DTLS_1_0_CLIENT_ENCRYPTED_ALERT_MBED_CLIENT, DTLS_1_0_CERT_FRAGMENT]

    # malformed packets na bazie DTLS_1_0
    data = DTLS_1_0_HELLO_NMAP.decode('hex')
    # dtls_1_0_hello = DTLSRecord(data)
    # dtls_1_2_hello.version = 0xfefd # DTLS 1.2

    dtls_hello_malformed_version = DTLSRecord(data)
    dtls_hello_malformed_version.version = 0x0000  # malformed DTLS version
    dtls_hello_malformed_version[DTLSClientHello].version = 0x0000  # malformed DTLS version
    # dtls_hello_malformed_version.show()
    test_packets.append(str(dtls_hello_malformed_version).encode('hex'))

    dtls_1_0_hello_malformed_ctype = DTLSRecord(data)
    dtls_1_0_hello_malformed_ctype.content_type = 0xFF  # malformed content type
    # dtls_1_0_hello_malformed_ctype.show()
    test_packets.append(str(dtls_1_0_hello_malformed_ctype).encode('hex'))

    dtls_1_0_hello_malformed_epoch = DTLSRecord(data)
    dtls_1_0_hello_malformed_epoch.epoch = 0xFF  # malformed epoch
    # dtls_1_0_hello_malformed_epoch.show()
    test_packets.append(str(dtls_1_0_hello_malformed_epoch).encode('hex'))

    dtls_1_0_hello_malformed = DTLSRecord(data)
    dtls_1_0_hello_malformed.sequence = 0xFF  # malformed sequence
    # dtls_1_0_hello_malformed.show()
    test_packets.append(str(dtls_1_0_hello_malformed).encode('hex'))

    dtls_1_0_hello_malformed = DTLSRecord(data)
    # dtls_1_0_hello_malformed[DTLSClientHello].cookie = '010000000000'
    dtls_1_0_hello_malformed[DTLSClientHello].cookie_length = 0x0002  # malformed cookie len
    # dtls_1_0_hello_malformed.show()
    test_packets.append(str(dtls_1_0_hello_malformed).encode('hex'))

    # malformed packets na bazie DTLS_1_0

    data = DTLS_1_2_HELLO_OPENSSL_CLIENT.decode('hex')
    dtls_1_2_hello = DTLSRecord(data)
    dtls_1_2_hello.version = 0xfefd  # DTLS 1.2
    data = str(dtls_1_2_hello)
    # dtls_1_2_hello.show()
    # test_packets.append(str(dtls_1_2_hello).encode('hex'))

    dtls_hello_malformed_version = DTLSRecord(data)
    dtls_hello_malformed_version.version = 0xfefd  # DTLS 1.2
    dtls_hello_malformed_version[DTLSClientHello].version = 0x0000  # malformed DTLS version
    # dtls_hello_malformed_version.show()
    test_packets.append(str(dtls_hello_malformed_version).encode('hex'))

    dtls_1_0_hello_malformed_ctype = DTLSRecord(data)
    dtls_1_0_hello_malformed_ctype.content_type = 0xFF  # malformed content type
    # dtls_1_0_hello_malformed_ctype.show()
    test_packets.append(str(dtls_1_0_hello_malformed_ctype).encode('hex'))

    dtls_1_0_hello_malformed_epoch = DTLSRecord(data)
    dtls_1_0_hello_malformed_epoch.epoch = 0xFF  # malformed epoch
    # dtls_1_0_hello_malformed_epoch.show()
    test_packets.append(str(dtls_1_0_hello_malformed_epoch).encode('hex'))

    dtls_1_0_hello_malformed = DTLSRecord(data)
    dtls_1_0_hello_malformed.sequence = 0xFF  # malformed sequence
    # dtls_1_0_hello_malformed.show()
    test_packets.append(str(dtls_1_0_hello_malformed).encode('hex'))

    dtls_1_0_hello_malformed = DTLSRecord(data)
    # dtls_1_0_hello_malformed[DTLSClientHello].cookie = '010000000000'
    dtls_1_0_hello_malformed[DTLSClientHello].cookie_length = 0x0002  # malformed cookie len
    # dtls_1_0_hello_malformed.show()
    test_packets.append(str(dtls_1_0_hello_malformed).encode('hex'))
    return test_packets


def dtls_convert_version(response):
    """Converts DTLS server response to attribute version used by classifier"""
    versions = {"DTLS_1_0", "DTLS_1_1"}
    for ver_in in versions:
        if ver_in in response:
            return ver_in
    return "empty"


def dtls_convert_type(response):
    """Converts DTLS server response to attribute type used by classifier"""
    types = {"alert", "handshake"}
    for type_in in types:
        if "type      = "+type_in in response:
            return type_in
    return "empty"


def dtls_convert_description(response):
    """Converts DTLS server response to attribute description used by classifier"""
    descriptions = {"unexpected_message", "protocol_version", "decode_error",
                    "illegal_parameter", "handshake_failure"}
    for descr in descriptions:
        if descr in response:
            return descr
    return "empty"


def dtls_convert_length(response):
    """Converts DTLS server response to attribute length used by classifier"""
    return len(response)


class DTLSResults(object):
    """Wrapper for all DTLS results"""
    def __init__(self):
        self.version = "no_response"
        self.type = "no_response"
        self.description = "no_response"
        self.length = "no_response"

    def __str__(self):
        return "version = {} type = {} description = {} length = {}".format(self.version,
                                                                            self.type,
                                                                            self.description,
                                                                            self.length)

    def fill(self, version, type_name, description, length):
        """Setter for all parameters"""
        self.version = version
        self.type = type_name
        self.description = description
        self.length = length

    def convert(self, response):
        """Converts all parameters of DTLS response"""
        self.version = dtls_convert_version(response)
        self.type = dtls_convert_type(response)
        self.description = dtls_convert_description(response)
        self.length = dtls_convert_length(response)
