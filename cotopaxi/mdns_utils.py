# -*- coding: utf-8 -*-
"""Set of common utils for mDNS protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz,
#                Michał Radwański
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

import copy
import socket
import threading
import time

from dnslib import DNSRecord
from scapy.all import DNS, DNSQR, IP, UDP, Raw, sniff

from .common_utils import print_verbose, show_verbose, udp_sr1
from .protocol_tester import UDPBasedProtocolTester

DNS_SD_QUERY = "_services._dns-sd._udp.local"
DNS_SD_MULTICAST_IPV4 = "224.0.0.251"
DNS_SD_MULTICAST_IPV6 = "ff02::fb"
DNS_SD_MULTICAST_PORT = 5353


def convert_dns_ans(dns_ans, ancount):
    """Convert list of DNS answers to list of rrnames."""
    ans_tab = [dns_ans[index].rrname.strip(b".") for index in range(ancount)]
    return ans_tab


class MulticastDNSSniffer(object):
    """Wrapper for all sniffer variables."""

    def __init__(self, test_params, query=DNS_SD_QUERY):
        """Create MulticastDNSSniffer with default values."""
        self.test_params = test_params
        self.server_alive = False
        self.server_response = []
        self.query = query
        self.start_time = time.time()

    def filter_string(self):
        """Create filter string for scapy sniff() function."""
        if self.test_params.ip_version == 4:
            return (
                "udp and (dst host "
                + DNS_SD_MULTICAST_IPV4
                + " or dst host "
                + str(self.test_params.src_endpoint.ip_addr)
                + ") and (src host "
                + str(self.test_params.dst_endpoint.ip_addr)
                + ") and (dst port 5353 or src port 5353)"
            )
        if self.test_params.ip_version == 6:
            return (
                "udp and (dst host "
                + DNS_SD_MULTICAST_IPV6
                + " or dst host "
                + str(self.test_params.src_endpoint.ipv6_addr)
                + ") and (src host "
                + str(self.test_params.dst_endpoint.ip_addr)
                + ") and (dst port 5353 or src port 5353)"
            )
        return None

    def filter_action(self, packet):
        """Count size of sniffed packet."""
        if UDP in packet:
            try:
                print_verbose(self.test_params, "[-] Received UDP packet")
                show_verbose(self.test_params, packet[IP])
                dns_resp_rrname = ""
                if DNS in packet:
                    dns_response = packet[DNS]
                    print_verbose(self.test_params, "[-] DNS packet parsed by scapy")
                    print_verbose(
                        self.test_params,
                        "dns_response[DNS].ancount = {}".format(
                            dns_response[DNS].ancount
                        ),
                    )
                    if dns_response[DNS].ancount > 0:
                        # print_verbose(self.test_params,
                        # "dns_response[DNS].an = {}".format(dns_response[DNS].an))
                        print_verbose(
                            self.test_params,
                            "dns_response[DNS].an[0].rrname = {}".format(
                                dns_response[DNS].an[0].rrname
                            ),
                        )
                        dns_resp_rrname = convert_dns_ans(
                            dns_response[DNS].an, dns_response[DNS].ancount
                        )
                        self.server_response = list(
                            set(dns_resp_rrname + self.server_response)
                        )
                        print_verbose(self.test_params, dns_resp_rrname)
                if Raw in packet:
                    dns_response = DNSRecord.parse(packet[Raw].load)
                    print_verbose(self.test_params, "[-] DNS Packet parsed by dnslib")
                    if self.test_params.verbose:
                        print_verbose(
                            self.test_params,
                            "Received DNS message: {}".format(dns_response),
                        )
                        print_verbose(
                            self.test_params,
                            "DNS message contains answer: {}".format(
                                dns_response.get_a()
                            ),
                        )
                        dns_resp_rrname = str(dns_response.get_a())
                        self.server_response = list(
                            set(dns_resp_rrname + self.server_response)
                        )

                if self.query in dns_resp_rrname or self.query == dns_resp_rrname:
                    self.server_alive = True
                    self.test_params.report_received_packet(self.start_time)
                    # answers = dns_response.header.a
                    # print("Answers = {}".format(answers))
            except (AttributeError, TypeError) as exc:
                print_verbose(self.test_params, str(exc))


def mdns_send_query(test_params, query, send_multicast=True):
    """Send mDNS query to normal and multicast address."""
    dns_sd_query = bytes(DNS(rd=1, qd=DNSQR(qname=query, qtype="PTR")))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    time.sleep(1)
    udp_sr1(test_params, dns_sd_query)
    if send_multicast:
        multicast_test_params = copy.deepcopy(test_params)
        if test_params.ip_version == 4:
            multicast_test_params.dst_endpoint.ip_addr = DNS_SD_MULTICAST_IPV4
            sock.sendto(
                bytes(dns_sd_query),
                (DNS_SD_MULTICAST_IPV4, multicast_test_params.dst_endpoint.port),
            )
        elif test_params.ip_version == 6:
            multicast_test_params.dst_endpoint.ip_addr = DNS_SD_MULTICAST_IPV6
            sock.sendto(
                str(dns_sd_query),
                (DNS_SD_MULTICAST_IPV6, multicast_test_params.dst_endpoint.port),
            )
        else:
            return


def mdns_query(test_params, query):
    """Perform mDNS query and returns response."""
    mdns_sniffer = MulticastDNSSniffer(test_params, query)
    thread = threading.Thread(target=mdns_send_query, args=(test_params, query))
    thread.start()
    sniff(
        filter=mdns_sniffer.filter_string(),
        prn=mdns_sniffer.filter_action,
        count=10000,
        timeout=test_params.timeout_sec + 2,
    )
    if mdns_sniffer.server_alive:
        print(
            "[+] Server {}:{} responded for query: {} with following records:".format(
                test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port, query
            )
        )
        for response in mdns_sniffer.server_response:
            print("\t{}".format(response))
    else:
        print(
            "[-] Server {}:{} is not responding for query: {}".format(
                test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port, query
            )
        )
    return mdns_sniffer.server_response


class MDNSTester(UDPBasedProtocolTester):
    """Tester of mDNS protocol."""

    def __init__(self):
        """Create empty MDNSTester object."""
        UDPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "mDNS"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Multicast DNS"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 5353

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return DNS

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return DNS

    @staticmethod
    def ping(test_params, show_result=False):
        """Check mDNS service availability by sending ping packet and waiting for response."""
        if not test_params:
            return None
        query = DNS_SD_QUERY.encode()
        mdns_sniffer = MulticastDNSSniffer(test_params, query)
        thread = threading.Thread(target=mdns_send_query, args=(test_params, query))
        thread.start()
        print_verbose(test_params, "filter: {}".format(mdns_sniffer.filter_string()))
        try:
            sniff(
                filter=mdns_sniffer.filter_string(),
                prn=mdns_sniffer.filter_action,
                count=10000,
                timeout=test_params.timeout_sec + 2,
            )
        except socket.error:
            print_verbose(
                test_params,
                "[!] Skipping mDNS ping due to lack of admin caps for sniffing!",
            )
        print_verbose(
            test_params, "received mDNS response: {}".format(mdns_sniffer.server_alive)
        )
        return mdns_sniffer.server_alive

    @staticmethod
    def implements_resource_listing():
        """Return True if this tester implements resource for this protocol."""
        return True
