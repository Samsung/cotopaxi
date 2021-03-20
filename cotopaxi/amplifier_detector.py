# -*- coding: utf-8 -*-
"""Tool for detection of network traffic reflectors."""
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
import sys
import time

from scapy.all import IP, UDP, sniff

from .common_utils import amplification_factor, scrap_packet
from .cotopaxi_tester import (
    argparser_add_dest,
    argparser_add_number,
    argparser_add_verbose,
    check_caps,
    check_non_negative_float,
    parse_port,
)
from .mdns_utils import DNS_SD_MULTICAST_IPV4, DNS_SD_MULTICAST_IPV6

UNICAST_ADDRESSES = [DNS_SD_MULTICAST_IPV4, DNS_SD_MULTICAST_IPV6]


class ReflectorSniffer(object):
    """Wrapper for all sniffer variables."""

    class Statistics(object):
        """Class handling internal statistics of sniffer."""

        def __init__(self):
            """Create empty ReflectorSniffer object."""
            self.packets_in_nr = 0
            self.packets_out_nr = 0
            self.packets_in_size = 0
            self.packets_out_size = 0
            self.packet_record_amplify = 0
            self.packet_record_desc = "[.] No interesting amplification cases!"

        def count_packet(self, packet, direction_in):
            """Count size of sniffed packet."""
            if direction_in:
                self.packets_in_nr += 1
                self.packets_in_size += len(packet)
            else:
                self.packets_out_nr += 1
                self.packets_out_size += len(packet)

        def update_record_amplify(self, from_target, to_target, ampl_factor):
            """Update packet with highest amplify factor."""
            self.packet_record_amplify = ampl_factor
            desc = [
                "[+] Highest amplify packet factor: {:0.2f}%".format(ampl_factor),
                "TO TARGET",
                scrap_packet(to_target),
                "FROM TARGET",
                scrap_packet(from_target),
                80 * "-",
            ]
            self.packet_record_desc = "\n".join(desc)
            return self.packet_record_desc

    def __init__(self, options):
        """Create ReflectorSniffer object based on provided options."""
        self.input_options = options
        self.stats = self.Statistics()
        self.time_displayed = time.time()
        self.last_packet_in = None

    def filter_action(self, packet):
        """Count size of sniffed packet."""
        if self.input_options:
            observed_ip_addr = self.input_options.dest_ip
            observed_port = parse_port(self.input_options.port)
        else:
            observed_ip_addr = "1.1.1.1"
            observed_port = None

        if IP in packet and UDP in packet:
            if (
                packet[IP].src == observed_ip_addr
                and packet[IP].dst not in UNICAST_ADDRESSES
            ):
                self.stats.count_packet(packet, False)
                if (
                    self.last_packet_in
                    and self.last_packet_in[IP].src == packet[IP].dst
                    and self.last_packet_in[UDP].sport == packet[UDP].dport
                ):
                    ampl_factor = amplification_factor(
                        len(self.last_packet_in), len(packet)
                    )
                    if self.input_options.verbose:
                        print(
                            "Amplification factor of current packet: "
                            "{:0.2f}%".format(ampl_factor)
                        )
                    if ampl_factor > self.stats.packet_record_amplify:
                        print(
                            self.stats.update_record_amplify(
                                packet, self.last_packet_in, ampl_factor
                            )
                        )

            elif packet[IP].dst == observed_ip_addr:
                self.stats.count_packet(packet, True)
                self.last_packet_in = packet
        if time.time() - self.time_displayed > self.input_options.interval:
            self.time_displayed = time.time()
            if observed_port:
                target = "{}:{}".format(observed_ip_addr, observed_port)
            else:
                target = observed_ip_addr
            return (
                "TARGET: {} | TO TARGET packets: {}, bytes: {} | FROM TARGET "
                "packets: {}, bytes: {} | AMPLIF FACTOR: {:0.2f}%"
            ).format(
                target,
                self.stats.packets_in_nr,
                self.stats.packets_in_size,
                self.stats.packets_out_nr,
                self.stats.packets_out_size,
                amplification_factor(
                    self.stats.packets_in_size, self.stats.packets_out_size
                ),
            )
        return None

    def __str__(self):
        """Prepare results of sniffing in str form."""
        if self.stats.packet_record_desc:
            return self.stats.packet_record_desc
        return ""


def amplifier_parse_args(args):
    """Parse arguments for amplifier."""
    parser = argparse.ArgumentParser()
    parser = argparser_add_verbose(parser)
    parser = argparser_add_dest(parser)
    parser = argparser_add_number(parser)
    parser.add_argument(
        "--interval",
        "-I",
        action="store",
        default=1,
        type=check_non_negative_float,
        help="minimal interval in sec "
        "between displayed status messages (default: 1 sec)",
    )
    return parser.parse_args(args)


def main(args):
    """Set up reflector detection sniffer based on command line parameters."""
    check_caps()
    options = amplifier_parse_args(args)

    dest_ip = options.dest_ip
    dest_port = parse_port(options.port)

    sniffer = ReflectorSniffer(options)

    # Setup sniff, filtering for IP traffic
    filter_string = "udp and host " + dest_ip
    if dest_port is not None and dest_port > 0:
        filter_string += " and port " + str(dest_port)

    print("[.] Starting sniffing with filter: {}".format(filter_string))

    try:
        if options.nr > 0:
            print("Press CTRL-C to finish")
            sniff(filter=filter_string, prn=sniffer.filter_action, count=options.nr)
        print("[.] Finished sniffing")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        print(sniffer)


if __name__ == "__main__":
    main(sys.argv[1:])
