# -*- coding: utf-8 -*-
"""Generic tester for Cotopaxi tools."""
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

import argparse
import socket
import struct
import sys
import time
from IPy import IP as IPY_IP
from scapy.all import sniff, TCP, UDP
from scapy.error import Scapy_Exception
import validators

from .common_utils import (
    get_local_ip,
    get_local_ipv6_address,
    get_random_high_port,
    NET_MAX_PORT,
    prepare_separator,
    print_verbose,
    Protocol,
    SCAPY_SSL_TLS_NOT_INSTALLED,
    ssdp_send_query,
    tcp_sr1,
    udp_sr1,
)
from .amqp_utils import AMQPTester
from .coap_utils import CoAPTester
from .htcpcp_utils import HTCPCPTester
from .http_utils import HTTPTester
from .knx_utils import KNXTester
from .mdns_utils import MDNSTester
from .mqtt_utils import MQTTTester
from .mqttsn_utils import MQTTSNTester
from .quic_utils import QUICTester
from .rtsp_utils import RTSPTester
from .ssdp_utils import SSDPTester


class CotopaxiException(Exception):
    """Critical exception used by Cotopaxi."""


PROTOCOL_TESTERS = {
    Protocol.AMQP: AMQPTester,
    Protocol.CoAP: CoAPTester,
    Protocol.HTCPCP: HTCPCPTester,
    Protocol.HTTP: HTTPTester,
    Protocol.KNX: KNXTester,
    Protocol.mDNS: MDNSTester,
    Protocol.MQTT: MQTTTester,
    Protocol.MQTTSN: MQTTSNTester,
    Protocol.RTSP: RTSPTester,
    Protocol.QUIC: QUICTester,
    Protocol.SSDP: SSDPTester,
}

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

try:
    from .dtls_utils import DTLSTester

    PROTOCOL_TESTERS[Protocol.DTLS] = DTLSTester
except (ImportError, ModuleNotFoundError):
    print(SCAPY_SSL_TLS_NOT_INSTALLED)


def protocols_using(transport_protocol):
    """Provide list of protocols using provided transport protocol."""
    return [
        e
        for e, p in PROTOCOL_TESTERS.items()
        if p.transport_protocol() == transport_protocol
    ]


def protocol_enabled(protocol, proto_mask):
    """Check whether protocol is enabled for test using given protocol mask."""
    if proto_mask == Protocol.ALL:
        return True
    if proto_mask == protocol:
        return True
    if proto_mask == Protocol.TCP and protocol in protocols_using(Protocol.TCP):
        return True
    if proto_mask == Protocol.UDP and protocol in protocols_using(Protocol.UDP):
        return True
    return False


# Time in sec to be delayed to show disclaimer
SLEEP_TIME_ON_DISCLAIMER = 1


def argparser_add_verbose(parser):
    """Add verbose parameter to arg parser."""
    parser.add_argument(
        "--verbose",
        "-V",
        "--debug",
        "-D",
        action="store_true",
        help="turn on verbose/debug mode (more messages)",
    )
    return parser


def argparser_add_protocols(parser, test_name, use_generic_proto):
    """Add protocols to arg parser."""
    supported_protocols = [
        p.protocol_short_name()
        for p in PROTOCOL_TESTERS.values()
        if getattr(p, "implements_" + test_name.replace(" ", "_"))()
    ]
    supported_protocols = sorted(supported_protocols, key=str.lower)
    if use_generic_proto:
        generic = ["ALL", "UDP", "TCP"]
        protocols = generic + supported_protocols
        parser.add_argument(
            "--protocol",
            "-P",
            action="store",
            choices=protocols,
            default="ALL",
            help="protocol to be tested (UDP includes all UDP-based protocols,"
            " while TCP includes all TCP-based protocols, "
            "ALL includes all supported protocols)",
        )
    else:
        default_proto = "CoAP"
        if len(supported_protocols) == 1:
            default_proto = supported_protocols[0]
        parser.add_argument(
            "--protocol",
            "-P",
            action="store",
            choices=supported_protocols,
            default=default_proto,
            help="protocol to be tested",
        )


def argparser_add_dest(parser):
    """Add verbose parameter to arg parser."""
    parser.add_argument("dest_ip", action="store", help="destination IP address")
    parser.add_argument(
        "--port", "--dest_port", "-P", action="store", help="destination port"
    )
    return parser


def argparser_add_number(parser):
    """Add verbose parameter to arg parser."""
    parser.add_argument(
        "--nr",
        "-N",
        action="store",
        type=int,
        default=9999999,
        help="number of packets to be sniffed (default: 9999999)",
    )
    return parser


def argparser_add_ignore_ping_check(parser):
    """Add ignore ping check parameter to arg parser."""
    parser.add_argument(
        "--ignore-ping-check",
        "-Pn",
        action="store_true",
        help="ignore ping check (treat all ports as alive)",
    )
    return parser


def create_basic_argparser():
    """Create ArgumentParser and add basic options (dest_addr, dest_port and verbose).

    Returns:
        ArgumentParser: Parser with added options used by all programs.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "dest_addr",
        action="store",
        help="destination hostname, IP address or multiple IPs "
        "separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask "
        "(e.g. '10.0.0.0/22') or both",
    )
    parser.add_argument(
        "dest_port",
        action="store",
        help="destination port or multiple ports "
        "given by list separated by coma (e.g. '8080,9090') or port range "
        "(e.g. '1000-2000') or both",
    )
    parser.add_argument(
        "--retries", "-R", action="store", type=int, default=0, help="number of retries"
    )
    parser.add_argument(
        "--timeout",
        "-T",
        action="store",
        type=check_non_negative_float,
        default=1,
        help="timeout in seconds",
    )
    parser.add_argument(
        "--verbose",
        "-V",
        "--debug",
        "-D",
        action="store_true",
        help="Turn on verbose/debug mode (more messages)",
    )
    return parser


def create_client_tester_argparser():
    """Create ArgumentParser and add options for client tester.

    Returns:
        ArgumentParser: Parser with added options used by all programs.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server-ip",
        "-SI",
        action="store",
        help="IP address, that will be used to set up tester server",
        default="0.0.0.0",  # nosec
    )
    parser.add_argument(
        "--server-port",
        "-SP",
        action="store",
        type=int,
        default=-1,
        help="port that will be used to set up server",
    )
    parser.add_argument(
        "--verbose",
        "-V",
        "--debug",
        "-D",
        action="store_true",
        help="Turn on verbose/debug mode (more messages)",
    )
    return parser


def check_non_negative_float(value):
    """Check whether provided string value converts to non-negative float value."""
    ivalue = float(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError(
            "{} is an invalid non-negative value".format(value)
        )
    return ivalue


class TestStatistics(object):
    """Object gathering test statistics."""

    def __init__(self):
        """Create test statistics with zeroed values."""
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
        """Calculate test time in seconds."""
        return time.time() - self.test_start


class Endpoint(object):
    """Object representing test endpoint (source or destination)."""

    def __init__(self, ip_addr=None, port=None, ipv6_addr=None):
        """Create empty Endpoint object."""
        if ip_addr is None:
            self.ip_addr = get_local_ip()
        else:
            self.ip_addr = ip_addr
        if ipv6_addr is None:
            self.ipv6_addr = get_local_ipv6_address()
        else:
            self.ipv6_addr = ipv6_addr
        if port is None:
            self.port_ = get_random_high_port()
        else:
            self.port_ = port

    @property
    def ip_address(self):
        """Return IP address of this endpoint."""
        return self.ip_addr

    @ip_address.setter
    def ip_address(self, ip_value):
        """Set IP address of this endpoint."""
        self.ip_addr = ip_value

    @property
    def port(self):
        """Return port of this endpoint."""
        return self.port_

    @port.setter
    def port(self, port):
        """Set port of this endpoint."""
        self.port_ = port


def message_loss(sent, received):
    """Calculate message loss factor."""
    if sent > 0 and received <= sent:
        return 100.0 * (sent - received) / sent
    return 0


def print_disclaimer():
    """Show legal disclaimer."""
    print(prepare_separator())
    print(
        """This tool can cause some devices or servers to stop acting in the intended way -
for example leading to crash or hang of tested entities or flooding
with network traffic other entities!
Make sure you have permission from the owners of tested devices or servers
before running this tool!"""
    )
    print(prepare_separator())
    time.sleep(SLEEP_TIME_ON_DISCLAIMER)


def check_caps(message="This tool"):
    """Check privileges required to run scapy sniffing functions."""
    try:
        sniff(count=1, timeout=0.01)
    except socket.error:
        sys.exit(
            "\n" + message + " requires admin permissions on network interfaces.\n"
            "On Linux and Unix run it with sudo, use root account (UID=0)"
            " or add CAP_NET_ADMIN, CAP_NET_RAW manually!\n"
            "On Windows run as Administrator.\n"
        )


class TestParams(object):
    """Object defining common test parameters."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self, name=""):
        """Create empty TestParams object."""
        self.test_name = name
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
        """Print statistics gathered during tests."""
        print(prepare_separator(post_separator_text="Test statistics:"))
        print(
            "Messages sent: {}, responses received: {}, "
            "{:.0f}% message loss, test time: {:.0f} ms".format(
                self.test_stats.packets_sent,
                self.test_stats.packets_received,
                message_loss(
                    self.test_stats.packets_sent, self.test_stats.packets_received
                ),
                1000 * self.test_stats.test_time(),
            )
        )
        if self.test_stats.packets_rtt:
            print(
                "Round-Trip Time (min/avg/max): {} / {} / {} ms".format(
                    min(self.test_stats.packets_rtt),
                    sum(self.test_stats.packets_rtt) / len(self.test_stats.packets_rtt),
                    max(self.test_stats.packets_rtt),
                )
            )
        if not self.positive_result_name:
            return
        print(prepare_separator(post_separator_text="Test results:"))
        active_endpoints = set()
        potential_endpoints = set()
        inactive_endpoints = set()
        print("{}:".format(self.positive_result_name))
        for proto in self.test_stats.active_endpoints:
            proto_results = self.test_stats.active_endpoints[proto]
            if proto_results:
                print("    For {}: {}".format(proto, proto_results))
                active_endpoints.update(set(proto_results))
        print(
            "Total number of {}: {}".format(
                self.positive_result_name.lower(), len(active_endpoints)
            )
        )
        if self.potential_result_name:
            for (
                proto,
                inactive_endpoint,
            ) in self.test_stats.inactive_endpoints.items():
                inactive_endpoints.update(set(inactive_endpoint))
            if potential_endpoints:
                print(
                    "{}: {}".format(
                        self.potential_result_name, len(potential_endpoints)
                    )
                )
            potential_results = []
            for (proto, proto_results) in self.test_stats.potential_endpoints.items():
                if proto_results:
                    potential_results.append(
                        "    For {}: {}".format(proto, proto_results)
                    )
                potential_endpoints.update(set(proto_results))
            if potential_results:
                print(self.potential_result_name + ":\n")
                print("\n".join(potential_results))
        if self.negative_result_name:
            inactive_endpoints.difference_update(active_endpoints)
            inactive_endpoints.difference_update(potential_endpoints)
            print("{}: {}".format(self.negative_result_name, len(inactive_endpoints)))

    def print_client_stats(self):
        """Print statistics gathered during tests of clients."""
        print(prepare_separator(post_separator_text="Test statistics:"))
        print(
            "Requests received: {}, payloads sent: {}, "
            "test time: {:.0f} ms".format(
                self.test_stats.packets_sent,
                self.test_stats.packets_received,
                1000 * self.test_stats.test_time(),
            )
        )

    def report_sent_packet(self):
        """Update tests statistics with sent packet.

        Returns:
            time when packet was sent (input parameter for report_received_packet())
        """
        self.test_stats.packets_sent += 1
        return time.time()

    def report_received_packet(self, sent_time):
        """Update tests statistics with received packet.

        Args:
            sent_time: time when packet was sent (returned by report_sent_packet).
        """
        response_time = time.time()
        self.test_stats.packets_received += 1
        self.test_stats.packets_rtt.append(int(1000 * (response_time - sent_time)))

    @property
    def src(self):
        """Return source endpoint."""
        return self.src_endpoint

    @property
    def dst(self):
        """Return destination endpoint."""
        return self.dst_endpoint

    def set_ip_version(self):
        """Set IP version of the protocol."""
        ip_addr = IPY_IP(self.dst_endpoint.ip_addr)
        if ip_addr.version() == 6:
            self.ip_version = 6


def sr1_file(test_params, test_filename, display_packet=False):
    """Read test message from given file, sends this message to server and parses response."""
    with open(test_filename, "rb") as file_handle:
        test_packet = file_handle.read()
    if display_packet:
        # print("Protocol: {}".format(proto_mapping(test_params.protocol)))
        try:
            if test_params.protocol in PROTOCOL_TESTERS:
                out_packet = PROTOCOL_TESTERS[test_params.protocol].request_parser(
                    test_packet
                )
            out_packet.show()
            print_verbose(test_params, prepare_separator("-"))
        except (TypeError, struct.error, RuntimeError, ValueError, Scapy_Exception):
            pass
    test_result = None
    if test_params.protocol in [Protocol.SSDP]:
        test_result = ssdp_send_query(test_params, test_packet)
    elif test_params.protocol in protocols_using(UDP):
        test_result = udp_sr1(test_params, test_packet)
    elif test_params.protocol in protocols_using(TCP):
        test_result = tcp_sr1(test_params, test_packet)
    return test_result


class CotopaxiTester(object):
    """Core tester data and methods."""

    def __init__(
        self,
        test_name="",
        check_ignore_ping=False,
        use_generic_proto=True,
        show_disclaimer=True,
        protocol_choice=None,
    ):
        """Create empty CotopaxiTester object."""
        self.test_params = TestParams(test_name)
        self.list_ips = []
        self.list_ports = []
        self.argparser = create_basic_argparser()

        if protocol_choice:
            self.argparser.add_argument(
                "--protocol",
                "-P",
                action="store",
                choices=protocol_choice,
                default="ALL",
                help="protocol to be tested",
            )
        else:
            argparser_add_protocols(self.argparser, test_name, use_generic_proto)

        if show_disclaimer:
            self.argparser.add_argument(
                "--hide-disclaimer",
                "-HD",
                action="store_true",
                help="hides legal disclaimer (shown before starting "
                "intrusive tools)",
            )
        self.argparser.add_argument(
            "--src-ip",
            "-SI",
            action="store",
            type=str,
            help="source IP address (return result will not be received!)",
        )
        self.argparser.add_argument(
            "--src-port",
            "-SP",
            action="store",
            type=str,
            help="source port (if not specified random port will be used)",
        )
        if check_ignore_ping:
            argparser_add_ignore_ping_check(self.argparser)

    def parse_args(self, args):
        """Parse all parameters based on provided argparser options."""
        options = self.argparser.parse_args(args)
        self.test_params.verbose = options.verbose
        self.test_params.nr_retries = options.retries
        self.test_params.timeout_sec = options.timeout

        self.test_params.protocol = Protocol[options.protocol.replace("-", "")]
        try:
            if options.src_ip:
                check_caps("Spoofing source IP")
                self.test_params.src_endpoint.ip_addr = options.src_ip
        except AttributeError:
            pass

        self.test_params.parsed_options["show_disclaimer"] = (
            "hide_disclaimer" in options and not options.hide_disclaimer
        )

        try:
            if options.ignore_ping_check:
                self.test_params.ignore_ping_check = True
        except AttributeError:
            self.test_params.ignore_ping_check = False

        if options.verbose:
            print("options: {}".format(options))
            print("dest_addr: {}".format(options.dest_addr))
            print("dest_port: {}".format(options.dest_port))
            print("protocol: {}".format(options.protocol))

        if validators.domain(options.dest_addr) is True:
            try:
                self.list_ips = prepare_ips(socket.gethostbyname(options.dest_addr))
            except socket.gaierror:
                print("[!] Cannot resolve hostname: {}".format(options.dest_addr))
                sys.exit(2)
        else:
            self.list_ips = prepare_ips(options.dest_addr)

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
        """Perform tests using CotopaxiTester."""
        if (
            "show_disclaimer" in self.test_params.parsed_options
            and self.test_params.parsed_options["show_disclaimer"]
        ):
            print_disclaimer()

        print("[.] Started {}".format(test_name))
        try:
            for dest_ip in self.list_ips:
                for dest_port in self.list_ports:
                    self.test_params.dst_endpoint.ip_addr = dest_ip
                    self.test_params.dst_endpoint.port = dest_port
                    self.test_params.set_ip_version()
                    test_function(self.test_params, test_cases)
            print(
                "[.] Finished {} (for all addresses, ports and protocols)".format(
                    test_name
                )
            )
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.test_params.print_stats()


class CotopaxiClientTester(object):
    """Core client tester (server used for testing clients) data and methods."""

    def __init__(self, test_name=""):
        """Create CotopaxiClientTester object with default values."""
        self.test_params = TestParams(test_name)
        self.argparser = create_client_tester_argparser()
        argparser_add_protocols(self.argparser, test_name, False)

    def parse_args(self, args):
        """Parse all parameters based on provided argparser options."""
        options = self.argparser.parse_args(args)
        self.test_params.verbose = options.verbose
        self.test_params.protocol = Protocol[options.protocol]
        self.test_params.src_endpoint.ip_addr = options.server_ip
        if options.server_port != -1:
            if options.server_port < 0 or options.server_port > NET_MAX_PORT:
                sys.exit("Server port must be in range (0, {}).".format(NET_MAX_PORT))
            self.test_params.src_endpoint.port = options.server_port
        else:
            self.test_params.src_endpoint.port = PROTOCOL_TESTERS[
                self.test_params.protocol
            ].default_port()
        if self.test_params.src_endpoint.port < 1024:
            check_caps("Listening on port lower than 1024")

        if options.verbose:
            print("options: {}".format(options))
            print("server_ip: {}".format(self.test_params.src_endpoint.ip_addr))
            print("server_port:  {}".format(self.test_params.src_endpoint.port))
            print("protocol: {}".format(self.test_params.protocol))
        return options


def prepare_ips(ips_input):
    """Parse IPs description taken from command line into sorted list of unique ip addresses.

    Args:
        ips_input (str): IP addresses description in format: '1.1.1.1,2.2.2.2/31'.
    Returns:
        list: Sorted list of unique IP addresses
            e.g.: ['1.1.1.1', '2.2.2.2', '2.2.2.3'] for the above example.
    """
    try:
        test_ips = [
            ip_addr
            for address_desc in ips_input.split(",")
            for ip_addr in IPY_IP(address_desc, make_net=1)
        ]
    except (TypeError, ValueError) as value_error:
        print("Cannot parse IP address: {}".format(value_error))
        sys.exit(2)
    test_ips = sorted(set(map(str, test_ips)))
    return test_ips


def parse_port(port_desc):
    """Parse single port description taken from command line into int value."""
    try:
        if port_desc is not None:
            port = int(port_desc)
            return port
    except (TypeError, ValueError) as value_error:
        print("Could not parse port: {}".format(value_error))
    return None


def prepare_ports(port_input):
    """Parse multiple ports description taken from command line into sorted list of unique ports.

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
            ip_range = list(map(int, part.split("-", 1)))
            ip_range = set(range(ip_range[0], ip_range[-1] + 1))
            ports |= set(ip_range)

        ports = sorted(ports)

        for port in ports:
            if port < 0 or port > NET_MAX_PORT:
                print("Port not in range: {}".format(port))
                sys.exit(2)
        return ports
    except (TypeError, ValueError) as error:
        print("Cannot parse port: {}".format(error))
        sys.exit(2)
