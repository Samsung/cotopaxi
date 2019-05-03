# -*- coding: utf-8 -*-
"""Set of common utils used by different Cotopaxi tools."""
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

import struct
import argparse
from enum import Enum
import random
import sys
import ssl
import socket
import time
# from socket import socket, AF_INET, SOCK_DGRAM
# from dtls import do_patch
from scapy.all import sniff, IP, IPv6, UDP, TCP, Raw, sr1, DNS as mDNS
from scapy.contrib.coap import CoAP
from scapy.contrib.mqtt import MQTT
from scapy.layers.ssl_tls import DTLSRecord as DTLS
from IPy import IP as IPY_IP

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

# Default size of input buffer
INPUT_BUFFER_SIZE = 10000

# Number of characters in line of separator
SEPARATOR_LINE_SIZE = 80

# Time in sec to be delayed to show disclaimer
SLEEP_TIME_ON_DISCLAIMER = 1


def get_local_ip():
    """Returns IP address of local node."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("1.255.255.255", 80))
    local_ip = sock.getsockname()[0]
    sock.close()
    return local_ip


def get_local_ipv6_address():
    """Returns IPv6 address of local node."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.connect(('::1', 80))
    local_ip = sock.getsockname()[0]
    sock.close()
    return local_ip


# Minimum number of private (ephemeral or high) port for TCP and UDP protocols
NET_MIN_HIGH_PORT = 49152

# Maximal number of port for TCP and UDP protocols
NET_MAX_PORT = 65535


def get_random_high_port():
    """Returns random value for private (ephemeral or high) TCP or UDP port."""
    return random.randint(NET_MIN_HIGH_PORT, NET_MAX_PORT)


def print_verbose(test_params, message):
    """Prints messages displayed only in the verbose/debug mode."""
    if test_params.verbose:
        print(message)


def show_verbose(test_params, packet, protocol=None):
    """Parses response packet and scraps response from stdout."""
    if protocol:
        try:
            proto_handler = proto_mapping(protocol)
            packet = proto_handler(packet)
        except KeyError:
            return "Response is not parsable!"
    parsed_response = ""
    if test_params.verbose:
        capture = StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        packet.show()
        sys.stdout = save_stdout
        parsed_response = capture.getvalue()
    return parsed_response


def scrap_packet(packet):
    """Parses response packet and scraps response from stdout."""
    capture = StringIO()
    save_stdout = sys.stdout
    sys.stdout = capture
    packet.show()
    sys.stdout = save_stdout
    parsed_response = capture.getvalue()
    return parsed_response


class Protocol(Enum):
    """Enumeration of protocols supported by Cotopaxi"""
    ALL = 0
    UDP = 1
    TCP = 2
    CoAP = 3
    MQTT = 4
    DTLS = 5
    mDNS = 6


def proto_mapping(protocol):
    """Provides mapping of enum values to implementation classes."""
    return {Protocol.ALL: IP, Protocol.UDP: UDP, Protocol.TCP: TCP, Protocol.CoAP: CoAP,
            Protocol.mDNS: mDNS, Protocol.MQTT: MQTT, Protocol.DTLS: DTLS}[protocol]


def protocol_enabled(protocol, proto_mask):
    """Core tester data and methods"""
    if proto_mask == Protocol.ALL:
        return True
    if proto_mask == protocol:
        return True
    if proto_mask == Protocol.TCP and protocol == Protocol.MQTT:
        return True
    if proto_mask == Protocol.UDP and (protocol == Protocol.CoAP or protocol == Protocol.DTLS):
        return True
    return False


def argparser_add_verbose(parser):
    """Adds verbose parameter to arg parser."""
    parser.add_argument("--verbose", "-V", '--debug', '-D', action="store_true",
                        help="turn on verbose/debug mode (more messages)")
    return parser


def argparser_add_dest(parser):
    """Adds verbose parameter to arg parser."""
    parser.add_argument('dest_ip', action='store', help="destination IP address")
    parser.add_argument('--port', '--dest_port', '-P', action='store', help="destination port")
    return parser


def argparser_add_number(parser):
    """Adds verbose parameter to arg parser."""
    parser.add_argument("--nr", "-N", action="store", type=int, default=9999999,
                        help="number of packets to be sniffed (default: 9999999)")
    return parser


def argparser_add_ignore_ping_check(parser):
    """Adds ignore ping check parameter to arg parser."""
    parser.add_argument("--ignore-ping-check", "-Pn", action="store_true",
                        help="ignore ping check (treat all ports as alive)")
    return parser


def create_basic_argparser():
    """Creates ArgumentParser and add basic options (dest_ip, dest_port and verbose).

        Returns:
            ArgumentParser: Parser with added options used by all programs.

    """
    parser = argparse.ArgumentParser()
    parser.add_argument('dest_ip', action='store',
                        help="destination IP address or multiple IPs "
                             "separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask "
                             "(e.g. '10.0.0.0/22') or both")
    parser.add_argument('dest_port', action='store',
                        help="destination port or multiple ports "
                             "given by list separated by coma (e.g. '8080,9090') or port range "
                             "(e.g. '1000-2000') or both")
    parser.add_argument('--retries', '-R', action='store', type=int, default=0,
                        help='number of retries')
    parser.add_argument('--timeout', '-T', action='store', type=check_non_negative_float, default=1,
                        help='timeout in seconds')
    parser.add_argument("--verbose", "-V", '--debug', '-D', action="store_true",
                        help="Turn on verbose/debug mode (more messages)")
    return parser


def print_separator(used_char='='):
    """Print line separator using provided char"""
    print(SEPARATOR_LINE_SIZE * used_char)


def print_disclaimer():
    """Shows legal dislaimer """
    print_separator()
    print ("This tool can cause some devices or servers to stop acting in the intended way -\n"
           "for example leading to crash or hang of tested entities or flooding \n"
           "with network traffic other entities!\n"
           "Make sure you have permission from the owners of tested devices or servers \n"
           "before running this tool!")
    print_separator()
    time.sleep(SLEEP_TIME_ON_DISCLAIMER)


def check_caps():
    """Function check privileges required to run scapy sniffing functions."""
    try:
        sniff(count=1, timeout=1)
    except socket.error:
        print ("\nThis tool requires admin permissions on network interfaces.\n"
               "On Linux and Unix run it with sudo, use root account (UID=0)"
               " or add CAP_NET_ADMIN, CAP_NET_RAW manually!\n"
               "On Windows run as Administrator.\n")
        exit(-1)


def check_non_negative_float(value):
    """Checks whether provided string value converts to non-negative float value"""
    ivalue = float(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("{} is an invalid non-negative value".format(value))
    return ivalue


class TestStatistics(object):
    """Object gathering test statistics"""

    def __init__(self):
        self.packets_sent = 0
        self.packets_received = 0
        self.packets_rtt = []
        self.test_start = time.time()
        self.active_endpoints = {}
        self.potential_endpoints = {}
        self.inactive_endpoints = {}
        for proto in Protocol:
            self.active_endpoints[proto] = []
            self.potential_endpoints[proto] = []
            self.inactive_endpoints[proto] = []

    def test_time(self):
        """Calculates test time in seconds"""
        return time.time() - self.test_start


class Endpoint(object):
    """Object representing test endpoint (source or destination)"""

    def __init__(self, ip_addr=None, port=None, ipv6_addr=None):
        if ip_addr is None:
            self.ip_addr = get_local_ip()
        else:
            self.ip_addr = ip_addr
        if ipv6_addr is None:
            self.ipv6_addr = get_local_ipv6_address()
        else:
            self.ipv6_addr = ipv6_addr
        if port is None:
            self.port = get_random_high_port()
        else:
            self.port = port

    def get_ip(self):
        """ Returns IP address of this endpoint"""
        return self.ip_addr

    def get_port(self):
        """ Returns port of this endpoint"""
        return self.port


def message_loss(sent, received):
    """Calculates message loss factor"""
    if sent > 0 and received <= sent:
        return 100 * float(sent - received) / sent
    return 0


class TestParams(object):
    """Object defining common test parameters"""

    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.src_endpoint = Endpoint()
        self.dst_endpoint = Endpoint()
        self.parsed_options = {}
        self.protocol = Protocol.ALL
        self.timeout_sec = 1
        self.nr_retries = 0
        self.verbose = False
        self.ignore_ping_check = False
        self.ip_version = 4
        self.wrap_secure_layer = False
        self.test_stats = TestStatistics()
        self.positive_result_name = "Active endpoints"
        self.potential_result_name = "Results that needs to be tested manually"
        self.negative_result_name = "Inactive endpoints"

    def print_stats(self):
        """Prints statistics gathered during tests"""
        print(80*"=" + "\nTest statistics:")
        print("Messages sent: {}, responses received: {}, "
              "{:.0f}% message loss, test time: {:.0f} ms"
              .format(self.test_stats.packets_sent,
                      self.test_stats.packets_received,
                      message_loss(self.test_stats.packets_sent,
                                   self.test_stats.packets_received),
                      1000*self.test_stats.test_time()))
        if self.test_stats.packets_rtt:
            print("Round-Trip Time (min/avg/max): {} / {} / {} ms"
                  .format(min(self.test_stats.packets_rtt),
                          sum(self.test_stats.packets_rtt) / len(self.test_stats.packets_rtt),
                          max(self.test_stats.packets_rtt)))
        if not self.positive_result_name:
            return
        print(80*"=" + "\nTest results:")
        active_endpoints = set()
        potential_endpoints = set()
        inactive_endpoints = set()
        print("{}:".format(self.positive_result_name))
        for proto in self.test_stats.active_endpoints:
            proto_results = self.test_stats.active_endpoints[proto]
            if proto_results:
                print("    For {}: {}".format(proto, proto_results))
                active_endpoints.update(set(proto_results))
        print("Total number of {}: {}".format(self.positive_result_name.lower(),
                                              len(active_endpoints)))
        if self.potential_result_name:
            for proto in self.test_stats.inactive_endpoints:
                inactive_endpoints.update(set(self.test_stats.inactive_endpoints[proto]))
            if potential_endpoints:
                print("{}: {}".format(
                    self.potential_result_name, len(potential_endpoints)))
            potential_results = ""
            for proto in self.test_stats.potential_endpoints:
                proto_results = self.test_stats.potential_endpoints[proto]
                if proto_results:
                    potential_results += "    For {}: {}".format(proto, proto_results)
                potential_endpoints.update(set(self.test_stats.potential_endpoints[proto]))
            if potential_results:
                print("{}:\n".format(self.potential_result_name) + potential_results)
        if self.negative_result_name:
            inactive_endpoints.difference_update(active_endpoints)
            inactive_endpoints.difference_update(potential_endpoints)
            print("{}: {}".format(self.negative_result_name, len(inactive_endpoints)))

    def report_sent_packet(self):
        """Updated tests statistics with sent packet.
            :return: time when packet was sent (input parameter for report_received_packet())
        """
        self.test_stats.packets_sent += 1
        return time.time()

    def report_received_packet(self, sent_time):
        """Updated tests statistics with received packet.
            :param sent_time: time when packet was sent (returned by report_sent_packet).
        """
        response_time = time.time()
        self.test_stats.packets_received += 1
        self.test_stats.packets_rtt.append(int(1000 * (response_time - sent_time)))

    def get_src(self):
        """Returns source endpoint"""
        return self.src_endpoint

    def get_dst(self):
        """Returns destination endpoint"""
        return self.dst_endpoint

    def set_ip_version(self):
        """Function identifies IP version of the protocol"""
        ip_addr = IPY_IP(self.dst_endpoint.ip_addr)
        if ip_addr.version() == 6:
            self.ip_version = 6


class CotopaxiTester(object):
    """Core tester data and methods"""

    def __init__(self, check_ignore_ping=False, use_generic_proto=True, show_disclaimer=True):
        check_caps()
        self.test_params = TestParams()
        self.list_ips = []
        self.list_ports = []
        self.argparser = create_basic_argparser()

        if use_generic_proto:
            self.argparser.add_argument('--protocol', '-P', action='store',
                                        choices=('UDP', 'TCP', 'CoAP', 'mDNS',
                                                 'MQTT', 'DTLS', 'ALL'),
                                        default='ALL',
                                        help="protocol to be tested (UDP includes CoAP, "
                                             "mDNS and DTLS, TCP includes CoAP and MQTT, "
                                             "ALL includes all supported protocols)")
        else:
            self.argparser.add_argument('--protocol', '-P', action='store',
                                        choices=('CoAP', 'mDNS', 'MQTT', 'DTLS'),
                                        default='CoAP',
                                        help="protocol to be tested")
        if show_disclaimer:
            self.argparser.add_argument('--hide-disclaimer', '-HD', action="store_true",
                                        help="hides legal disclaimer (shown before starting "
                                             "intrusive tools)")
        self.argparser.add_argument('--src-ip', '-SI', action='store', type=str,
                                    help="source IP address (return result will not be received!)")
        self.argparser.add_argument('--src-port', '-SP', action='store', type=str,
                                    help="source port (if not specified random port will be used)")
        if check_ignore_ping:
            argparser_add_ignore_ping_check(self.argparser)

    def get_test_params(self):
        """Returns parametrs of single test"""
        return self.test_params


    def parse_args(self, args):
        """Parses all parameters based on provided argparser options"""
        options = self.argparser.parse_args(args)
        self.test_params.verbose = options.verbose
        self.test_params.nr_retries = options.retries
        self.test_params.timeout_sec = options.timeout

        self.test_params.protocol = {'ALL': Protocol.ALL, 'UDP': Protocol.UDP,
                                     'TCP': Protocol.TCP, 'CoAP': Protocol.CoAP,
                                     'mDNS': Protocol.mDNS,
                                     'MQTT': Protocol.MQTT, 'DTLS': Protocol.DTLS}[options.protocol]
        try:
            if options.src_ip:
                self.test_params.src_endpoint.ip_addr = options.src_ip
        except AttributeError:
            pass

        self.test_params.parsed_options['show_disclaimer'] \
            = 'hide_disclaimer' in options and not options.hide_disclaimer

        try:
            if options.ignore_ping_check:
                self.test_params.ignore_ping_check = True
        except AttributeError:
            self.test_params.ignore_ping_check = False

        if options.verbose:
            print("options: {}".format(options))
            print("dest_ip: {}".format(options.dest_ip))
            print("dest_port: {}".format(options.dest_port))
            print("protocol: {}".format(options.protocol))

        self.list_ips = prepare_ips(options.dest_ip)
        self.list_ports = prepare_ports(options.dest_port)

        if options.verbose:
            print("src_ip: {}".format(self.test_params.src_endpoint.ip_addr))
            print("src_port:  {}".format(self.test_params.src_endpoint.port))
            print("list_ips: {}".format(self.list_ips))
            print("list_ports: {}".format(self.list_ports))
            print("protocol: {}".format(self.test_params.protocol))
            print("ignore-ping-check: {}".format(self.test_params.ignore_ping_check))
        return options

    def perform_testing(self, test_name, test_function, test_cases=None):
        """Wrapper used to perform tests using CotopaxiTester."""

        if ('show_disclaimer' in self.test_params.parsed_options and
                self.test_params.parsed_options['show_disclaimer']):
            print_disclaimer()

        print("[.] Started {}".format(test_name))
        try:
            for dest_ip in self.list_ips:
                for dest_port in self.list_ports:
                    self.test_params.dst_endpoint.ip_addr = dest_ip
                    self.test_params.dst_endpoint.port = dest_port
                    self.test_params.set_ip_version()
                    if test_cases:
                        test_function(self.test_params, test_cases)
                    else:
                        test_function(self.test_params)
            print("[.] Finished {} (for all addresses, ports and protocols)".format(test_name))
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.test_params.print_stats()


def prepare_ips(ips_input):
    """Parses IPs description taken from command line into sorted list of unique ip addresses.

        Args:
            ips_input (str): IP addresses description in format: '1.1.1.1,2.2.2.2/31'.

        Returns:
            list: Sorted list of unique IP addresses
                e.g.: ['1.1.1.1', '2.2.2.2', '2.2.2.3'] for the above example.
    """
    test_ips = []
    try:
        for address_desc in ips_input.split(","):
            for ip_addr in IPY_IP(address_desc, make_net=1):
                test_ips.append(str(ip_addr))
    except ValueError as value_error:
        print("Cannot parse IP address: {}".format(value_error))
        exit(-1)
    test_ips = sorted(set(test_ips))
    #    print test_ips
    return test_ips


def parse_port(port_desc):
    """Parses single port description taken from command line into int value."""
    try:
        if port_desc is not None:
            port = int(port_desc)
            return port
    except (TypeError, ValueError) as value_error:
        print("Could not parse port: {}".format(value_error))
    return None


def prepare_ports(port_input):
    """Parses multiple ports description taken from command line into sorted list of unique ports.

        Args:
            port_input (str): Ports description in format: '101,103-105,104,242'.

        Returns:
            list: Sorted list of unique IP addresses
                e.g.: [101, 103, 104, 105, 242] for the above example.

    """

    try:
        ports = set()
        parts = port_input.split(",")

        for part in parts:
            if '-' in part:
                part = part.split("-", 2)
                part_a, part_b = map(int, part)
                part = range(part_a, part_b + 1)
            else:
                part = {int(part)}

            ports |= set(part)

        ports = sorted(ports)
        return ports
    except ValueError as error:
        print("Cannot parse port: {}".format(error))
        exit(-1)


def tcp_sr1(test_params, test_packet):
    """Sends test message to server using TCP protocol and parses response."""
    in_data = None
    connect_handler = None
    sent_time = test_params.report_sent_packet()
    try:
        if test_params.ip_version == 4:
            connect_handler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_handler.settimeout(test_params.timeout_sec)
            connect_handler.connect((test_params.dst_endpoint.ip_addr,
                                     test_params.dst_endpoint.port))
        elif test_params.ip_version == 6:
            connect_handler = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            connect_handler.settimeout(test_params.timeout_sec)
            connect_handler.connect((test_params.dst_endpoint.ip_addr,
                                     test_params.dst_endpoint.port, 0, 0))
        connect_handler.send(str(test_packet))
        in_data = connect_handler.recv(INPUT_BUFFER_SIZE)
        if in_data:
            test_params.report_received_packet(sent_time)
    except (socket.timeout, socket.error) as exc:
        if test_params.verbose:
            print("TCP exception: {}".format(exc))
            # traceback.print_exc()
    finally:
        if connect_handler is not None:
            connect_handler.close()
    return in_data


def udp_sr1(test_params, udp_test, dtls_wrap=False):
    """Sends UDP test message to server using UDP protocol and parses response."""
    response = None
    sent_time = test_params.report_sent_packet()
    if not dtls_wrap:
        if test_params.ip_version == 4:
            udp_test_packet = IP() / UDP() / Raw(udp_test)
            udp_test_packet[IP].src = test_params.src_endpoint.ip_addr
            udp_test_packet[IP].dst = test_params.dst_endpoint.ip_addr
        elif test_params.ip_version == 6:
            udp_test_packet = IPv6() / UDP() / Raw(udp_test)
            udp_test_packet[IPv6].src = test_params.src_endpoint.ipv6_addr
            udp_test_packet[IPv6].dst = test_params.dst_endpoint.ip_addr
        udp_test_packet[UDP].sport = test_params.src_endpoint.port
        udp_test_packet[UDP].dport = test_params.dst_endpoint.port
        del udp_test_packet[UDP].chksum
        # if test_params.verbose:
        #     udp_test_packet.show()
        if test_params.timeout_sec == 0:
            test_params.timeout_sec = 0.0001
        response = sr1(udp_test_packet, verbose=test_params.verbose,
                       timeout=test_params.timeout_sec,
                       retry=test_params.nr_retries)
        if response:
            test_params.report_received_packet(sent_time)
    else:
        # do_patch()
        if test_params.ip_version == 4:
            sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            sock.connect((test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port))
            sock.send(udp_test)
            response = IP() / UDP() / Raw(sock.recv())
            if response:
                test_params.report_sent_packet(sent_time)

    #            sock.close()
    return response


def udp_sr1_file(test_params, test_filename):
    """Reads UDP test message from given file, sends this message to server and parses response"""
    with open(test_filename, "r") as file_handle:
        test_data = file_handle.read()
    return udp_sr1(test_params, test_data)


def sr1_file(test_params, test_filename, display_packet=False):
    """Reads test message from given file, sends this message to server and parses response"""
    with open(test_filename, "r") as file_handle:
        test_packet = file_handle.read()
    if display_packet:
        # print("Protocol: {}".format(proto_mapping(test_params.protocol)))
        try:
            out_packet = proto_mapping(test_params.protocol)(test_packet)
            out_packet.show()
            print_verbose(test_params, 60 * "-")
        except (TypeError, struct.error, RuntimeError, ValueError):
            pass
    test_result = None
    if test_params.protocol in [Protocol.CoAP, Protocol.DTLS, Protocol.mDNS]:
        test_result = udp_sr1(test_params, test_packet)
    if test_params.protocol in [Protocol.MQTT]:
        test_result = tcp_sr1(test_params, test_packet)
    return test_result


def prepare_names(name_filepath):
    """Loads names (URLs or services) from filepath taken from command line
    into sorted list of unique names.

        Args:
            name_filepath (str): Path to file with names.

        Returns:
            list: Sorted list of unique namess.
    """
    names_list = []
    try:
        with open(name_filepath, "r") as file_handle:
            names_list = file_handle.readlines()
        names_list = [name.strip() for name in names_list]
    except (IOError, OSError) as file_error:
        print("Cannot load names: {}".format(file_error))
        exit(-1)
    test_names = sorted(set(names_list))
    return test_names


def amplification_factor(input_size, output_size):
    """Calculates network traffic amplification factor for specific node
    Args:
        input_size(int): Size of traffic incoming to examined node.
        output_size(int): Size of traffic outgoing from examined node.

    Returns:
        int: Calculated amplification factor in percent
            (0 means that traffic incoming and outgoing are equal in size,
            100 means that outgoing traffic is two times larger than incoming)
    """
    if input_size != 0:
        return (100 * output_size / input_size) - 100
    return 0
