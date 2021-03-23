# -*- coding: utf-8 -*-
"""Tool for classifying network flows based on captured network traffic."""
#
#    Copyright (C) 2020-2021 Cotopaxi Contributors. All Rights Reserved.
#       Authors: Jakub Botwicz
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
from itertools import filterfalse
import logging
import os
import sys
import time

from scapy.all import IP, IPv6, TCP, UDP

try:
    import numpy
    from xgboost import XGBClassifier
except ImportError:
    sys.exit(
        "This tool requires numpy and xgboost!\n"
        "Please install them using: pip install cotopaxi[ml] or pip install -r requirements.txt"
    )

from .common_utils import prepare_separator
from .cotopaxi_tester import argparser_add_verbose, CotopaxiException, prepare_ips
from .device_identification import (
    df_from_scapy,
    ips_from_pcap,
    load_packets,
    normalizator,
    prepare_data,
)


UNKNOWN_PROTOCOL = "Unknown protocol"


def predict_xgb(data):
    """Perform prediction using trained model."""
    model = XGBClassifier()
    data = normalizator(prepare_data(data))
    try:
        model.load_model(
            os.path.dirname(__file__)
            + "/identification_models/proto_XGB_20201112.model"
        )
    except ValueError as exc:
        raise CotopaxiException from exc(
            "[!] Cannot load machine learning classifier!"
            "    This may be caused by incompatible version of tensorflow"
            "    (please install tensorflow version 2.2.0)!"
        )
    result = model.predict(data)
    unique, counts = numpy.unique(result, return_counts=True)
    devices = list()
    for unit in unique:
        devices.append(unit)
    result_dict = dict(zip(devices, counts))
    result_dict = sorted(result_dict.items(), key=lambda x: x[1], reverse=True)
    result_class = result_dict[0][0]
    return result_class, result_dict, counts.sum()


def split_packets(packets, ip_addr):
    """Split packets into bins by ports."""
    packets_bins_port = {}
    for packet in packets:
        if TCP in packet:
            transport_protocol = TCP
        elif UDP in packet:
            transport_protocol = UDP
        else:
            continue

        if IP in packet:
            network_protocol = IP
        elif IPv6 in packet:
            network_protocol = IPv6
        else:
            continue

        if ip_addr == packet[network_protocol].dst:
            packet[network_protocol].dst = packet[network_protocol].src
            packet[network_protocol].src = ip_addr
            temp_dst_port = packet[transport_protocol].dport
            packet[transport_protocol].dport = packet[transport_protocol].sport
            packet[transport_protocol].sport = temp_dst_port

        src_port = packet[transport_protocol].sport
        dst_ip = packet[network_protocol].dst
        dst_port = packet[transport_protocol].dport

        if (src_port, dst_ip, dst_port) not in packets_bins_port:
            packets_bins_port[(src_port, dst_ip, dst_port)] = list(packet)
        else:
            packets_bins_port[(src_port, dst_ip, dst_port)].append(packet)
    return packets_bins_port


def classify_traffic(
    packets,
    ip_addr,
    show_class=True,
    show_probability=True,
    min_packets=1,
    max_packets=1000,
):
    """Classify traffic based on provided network packets."""
    result_class = None
    packets_bins_port = split_packets(packets, ip_addr)
    for (src_port, dst_ip, dst_port) in packets_bins_port:
        packets = packets_bins_port[(src_port, dst_ip, dst_port)]
        data = df_from_scapy(packets, ip_addr, limit_packets=max_packets)
        if data is None:
            # print(
            #     f"[!] Packets with IP {ip_addr} were not found in the provided data capture!\n"
            #     f"[!] Classification stopped for IP {ip_addr}!"
            # )
            # return UNKNOWN_PROTOCOL
            continue
        if len(data) < min_packets:
            # print(
            #     f"[!] Not enough packets with IP {ip_addr} in the provided data capture!\n"
            #     f"[!] Classification stopped for IP {ip_addr}!"
            # )
            # return UNKNOWN_PROTOCOL
            continue

        if TCP in packets[0]:
            transport_protocol = "TCP"
        elif UDP in packets[0]:
            transport_protocol = "UDP"

        if IP in packets[0]:
            network_protocol = "IPv4"
        elif IPv6 in packets[0]:
            network_protocol = "IPv6"

        print(
            f"[.] Conversation: {ip_addr}:{src_port} <-> {dst_ip}:{dst_port} "
            f"| net + trans layers: {network_protocol} | {transport_protocol}"
        )
        print(f"[!] Found {len(data)} packets in this conversation")

        result_class, result_dict, sum_counts = predict_xgb(data)
        if show_class:
            print(f"[*]   Traffic was classified as:\n         {result_class}")

        if show_probability:
            print("[*]   Results of traffic classification:")
            for key, value in result_dict:
                print(f"           {key:>20}: {100*value/sum_counts:.2f}%")
    return result_class


def main(args):
    """Start traffic analysis based on command line parameters."""
    if sys.version_info[0] < 3:
        raise Exception("This tool must be run using Python 3!")
    parser = argparse.ArgumentParser(
        description="Tool for classifying network protocols used in traffic flows"
    )
    parser = argparser_add_verbose(parser)
    parser.add_argument(
        "pcap",
        help=(
            "Packet capture file (in PCAP or PCAPNG format) "
            "with recorded traffic for network protocols identification"
        ),
    )
    parser.add_argument(
        "--min",
        default=3,
        help="minimum number of packets to classify conversation"
        "(conversations with smaller number will not be classified) (default: 3)",
    )
    parser.add_argument(
        "--max",
        default=1000,
        help="maximum number of packets used to classify conversation (default: 1000)",
    )
    parser.add_argument("--ip", "-I", help="use IP filter to identify protocol")
    parser.add_argument(
        "-S",
        "--short",
        dest="short_result",
        help="display only short result of classification",
        action="store_true",
    )

    options = parser.parse_args(args)
    test_name = "traffic analysis"

    if options.verbose:
        print("options: {}".format(options))
    else:
        os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
        logging.getLogger("tensorflow").setLevel(logging.FATAL)

    packets = load_packets(options.pcap)

    if options.pcap and not options.ip:
        list_ips = ips_from_pcap(packets)
    else:
        list_ips = prepare_ips(options.ip)

    list_ips = list(filterfalse(lambda x: x.endswith(".0"), list_ips))
    list_ips = list(filterfalse(lambda x: x.endswith(".1"), list_ips))
    list_ips = list(filterfalse(lambda x: x.endswith(".255"), list_ips))
    list_ips = list(filterfalse(lambda x: x.startswith("224.0."), list_ips))
    list_ips = list(filterfalse(lambda x: x.startswith("232."), list_ips))
    list_ips = list(filterfalse(lambda x: x.startswith("233."), list_ips))
    list_ips = list(filterfalse(lambda x: x.startswith("234."), list_ips))
    list_ips = list(filterfalse(lambda x: x.startswith("239."), list_ips))
    list_ips = list(filterfalse(lambda x: x.startswith("ff0"), list_ips))

    if options.verbose:
        print("list_ips: {}".format(list_ips))

    print(f"[.] Started {test_name}")
    try:
        for test_ip in list_ips:
            print(prepare_separator("-"))
            print(f"[.] Started classification for IP: {test_ip}")
            start_time = time.time()
            classify_traffic(
                packets,
                test_ip,
                show_probability=not options.short_result,
                min_packets=int(options.min),
                max_packets=int(options.max),
            )
            classify_time = time.time() - start_time
            print(f"[.] Classification time: {classify_time:.2f} sec")
        print(prepare_separator("="))
        print(f"[.] Finished {test_name} (for all IPs)")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        pass
        # self.test_params.print_stats()


if __name__ == "__main__":
    main(sys.argv[1:])
