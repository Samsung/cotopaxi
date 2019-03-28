# -*- coding: utf-8 -*-
"""Tool for detection of network traffic reflectors."""
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
import time
import argparse
from scapy.all import sniff, IP, UDP
from .common_utils import check_caps, amplification_factor, argparser_add_verbose, \
    argparser_add_dest, argparser_add_number, parse_port, scrap_packet
from .mdns_utils import DNS_SD_MULTICAST_IPV4, DNS_SD_MULTICAST_IPV6

UNICAST_ADDRESSES = [
    DNS_SD_MULTICAST_IPV4, DNS_SD_MULTICAST_IPV6
    ]


class ReflectorSniffer(object):
    """Wrapper for all sniffer variables"""

    class Statistics(object):
        """Class handling internal statistics of sniffer."""

        def __init__(self):
            self.packets_in_nr = 0
            self.packets_out_nr = 0
            self.packets_in_size = 0
            self.packets_out_size = 0
            self.packet_record_amplify = 0
            self.packet_record_desc = None

        def count_packet(self, packet, direction_in):
            """Counts size of sniffed packet"""
            if direction_in:
                self.packets_in_nr += 1
                self.packets_in_size += len(packet)
            else:
                self.packets_out_nr += 1
                self.packets_out_size += len(packet)

    def __init__(self, options):
        self.input_options = options
        self.stats = self.Statistics()
        self.time_displayed = time.time()
        self.last_packet_in = None

    def filter_action(self, packet):
        """Counts size of sniffed packet"""

        if self.input_options:
            observed_ip_addr = self.input_options.dest_ip
            observed_port = parse_port(self.input_options.port)
        else:
            observed_ip_addr = "1.1.1.1"
            observed_port = None

        if IP in packet and UDP in packet:
            if packet[IP].src == observed_ip_addr and packet[IP].dst not in UNICAST_ADDRESSES:
                self.stats.count_packet(packet, False)
                if (self.last_packet_in and self.last_packet_in[IP].src == packet[IP].dst and
                        self.last_packet_in[UDP].sport == packet[UDP].dport):
                    ampl_factor = amplification_factor(len(self.last_packet_in), len(packet))
                    if self.input_options.verbose:
                        print("Amplification factor of current packet: {:0.2f}%"
                              .format(ampl_factor))
                    if ampl_factor > self.stats.packet_record_amplify:
                        self.stats.packet_record_amplify = ampl_factor
                        record_desc = "Highest amplify packet factor: {}%\n"\
                            .format(self.stats.packet_record_amplify)
                        record_desc += "\nTO TARGET:\n"
                        record_desc += scrap_packet(self.last_packet_in)
                        record_desc += "\n" + 80 * "-"
                        record_desc += "\nFROM TARGET:\n"
                        record_desc += scrap_packet(packet)
                        record_desc += "\n" + 80 * "-"
                        self.stats.packet_record_desc = record_desc
                        print(record_desc)
            else:
                if packet[IP].dst == observed_ip_addr:
                    self.stats.count_packet(packet, True)
                    self.last_packet_in = packet
        if time.time() - self.time_displayed > self.input_options.interval:
            self.time_displayed = time.time()
            if observed_port:
                target = "{}:{}".format(observed_ip_addr, observed_port)
            else:
                target = observed_ip_addr
            return (('TARGET: {} | TO TARGET packets: {}, bytes: {} | FROM TARGET '
                     'packets: {}, bytes: {} | AMPLIF FACTOR: {:0.2f}%')
                    .format(
                        target, self.stats.packets_in_nr, self.stats.packets_in_size,
                        self.stats.packets_out_nr, self.stats.packets_out_size,
                        amplification_factor(self.stats.packets_in_size,
                                             self.stats.packets_out_size)))
        return None

    def print_results(self):
        """Displays results of sniffing."""
        if self.stats.packet_record_desc:
            print(self.stats.packet_record_desc)

def check_non_negative_float(value):
    """Checks whether provided string value converts to non-negative float value"""
    ivalue = float(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("{} is an invalid non-negative value".format(value))
    return ivalue


def amplifier_parse_args(args):
    """Parses arguments for amplifier."""
    parser = argparse.ArgumentParser()
    parser = argparser_add_verbose(parser)
    parser = argparser_add_dest(parser)
    parser = argparser_add_number(parser)
    parser.add_argument("--interval", "-I", action="store", default=1,
                        type=check_non_negative_float, help="minimal interval in sec "
                        "between displayed status messages (default: 1 sec)")
    return parser.parse_args(args)


def main(args):
    """Sets up reflector detection sniffer based on command line parameters"""

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
        sniffer.print_results()


if __name__ == "__main__":
    main(sys.argv[1:])
