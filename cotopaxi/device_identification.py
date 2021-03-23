# -*- coding: utf-8 -*-
"""Tool for classifying IoT devices based on captured network traffic."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Mariusz Księżak (Samsung R&D Poland), Jakub Botwicz
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

from scapy.all import Scapy_Exception, IP, IPv6, PcapReader, TCP, UDP

try:
    import numpy
    import pandas
    from tensorflow.keras.models import load_model
except ImportError:
    sys.exit(
        "This tool requires pandas and tensorflow!\n"
        "Please install them using: pip install cotopaxi[ml] or pip install -r requirements.txt"
    )

from .common_utils import prepare_separator
from .cotopaxi_tester import argparser_add_verbose, CotopaxiException, prepare_ips


UNKNOWN_DEVICE_LABEL = "Unknown device (not in database or non-IoT)"

# NOTES
# UK & US
# array(['ikettle', 'fridge', 'echodot', 'tplink-bulb', 'washer', 'roku-tv',
#        'xiaomi-strip', 'tplink-plug', 'insteon-hub', 'smartthings-hub',
#        'lightify-hub', 'zmodo-doorbell', 'firetv', 'blink-security-hub',
#        'invoke', 'wink-hub2', 'magichome-strip', 'xiaomi-ricecooker',
#        'ring-doorbell', 'luohe-spycam', 'samsungtv-wired', 'microwave',
#        'xiaomi-hub', 'cloudcam', 'xiaomi-cleaner', 'wansview-cam-wired',
#        'lgtv-wired', 'echoplus', 'brewer', 'sengled-hub', 'bulb1',
#        'lefun-cam-wired', 'dryer', 'google-home-mini', 'echospot',
#        't-philips-hub', 'appletv', 'blink-camera', 'dlink-mov',
#        'philips-bulb', 't-wemo-plug', 'yi-camera', 'nest-tstat',
#        'sousvide', 'amcrest-cam-wired', 'microseven-camera',
#        'bosiwo-camera-wired', 'google-home', 'honeywell-thermostat',
#        'netatmo-weather-station', 'smarter-coffee-mach', 'charger-camera',
#        'xiaomi-cam2', 'allure-speaker'], dtype=object)


labels = numpy.array(
    [
        "Harman Kardon Allure",
        "Amcrest Camera",
        "Apple TV",
        "Blink Camera",
        "Blink Security Hub",
        "Bosiwo Camera",
        "Smarter Brewer",
        "Flux Bulb",
        "WiMaker Charger Camera",
        "Amazon Cloudcam",
        "D-Llink Mov Sensor",
        "Samsung Dryer",
        "Amazon Echo Dot",
        "Amazon Echo Plus",
        "Amazon Echo Spot",
        "Amazon Fire TV",
        "Samsung Fridge",
        "Google Home",
        "Google Home Mini",
        "Honeywell Thermostat",
        "Smarter iKettle",
        "Insteon Hub",
        "Harman Kardon Invoke",
        "Lefun Cam",
        "LG Smart TV",
        "Osram Lightify Hub",
        "Luohe Cam",
        "Magichome Strip",
        "Microseven Camera",
        "GE Microwave",
        "Nest Thermostat",
        "Netatmo Weather Station",
        "Philips Hue (Lightbulb)",
        "Ring Doorbell",
        "Roku TV",
        "Samsung SmartTV",
        "Sengled Smart Hub",
        "Smarter Coffee Machine",
        "Samsung SmartThings Hub",
        "Anova Sousvide",
        "Philips Hue Hub",
        "WeMo Plug",
        "TP-Link Bulb",
        "TP-Link Smart Plug",
        UNKNOWN_DEVICE_LABEL,
        "Wansview Camera",
        "Samsung Washer",
        "Wink Hub 2",
        "Xiaomi Mi Cam 2",
        "Xiaomi Mi Robot Cleaner",
        "Xiaomi Mi Hub",
        "Xiaomi Mi Rice Cooker",
        "Xiaomi Mi Power Strip",
        "Yi Camera",
        "Zmodo Greet (doorbell)",
    ],
    dtype=object,
)


def df_from_scapy(packets, ip_addr, limit_packets=1000):
    """Perform feature extraction from scapy packets."""
    start_time = 0
    list_of_data = list()
    for packet in packets:
        network_protocol = None
        transport_protocol = None
        data_dict = dict()
        if start_time == 0:
            start_time = packet.time
        data_dict["ts"] = packet.time - start_time
        if data_dict["ts"] > 5.0:
            data_dict["ts"] = 5.0

        if IP in packet:
            network_protocol = IP
            data_dict["ttl"] = packet[IP].ttl
            data_dict["len"] = packet[IP].len
            data_dict["proto"] = packet[IP].proto
        elif IPv6 in packet:
            network_protocol = IPv6
            data_dict["ttl"] = 0
            data_dict["len"] = packet[IPv6].plen
            data_dict["proto"] = packet[IPv6].nh
        else:
            data_dict["ttl"] = 0
            data_dict["len"] = len(packet)
            data_dict["proto"] = 0

        if TCP in packet:
            transport_protocol = TCP
            data_dict["sport"] = packet[transport_protocol].sport
            data_dict["dport"] = packet[transport_protocol].dport
            data_dict["tcp_flags"] = packet[TCP].flags
            data_dict["window"] = packet[TCP].window
        elif UDP in packet:
            transport_protocol = UDP
            data_dict["sport"] = packet[transport_protocol].sport
            data_dict["dport"] = packet[transport_protocol].dport
            data_dict["tcp_flags"] = 0
            data_dict["window"] = 0
        else:
            data_dict["sport"] = 0
            data_dict["dport"] = 0
            data_dict["tcp_flags"] = 0
            data_dict["window"] = 0
        if network_protocol and ip_addr in (
            packet[network_protocol].src,
            packet[network_protocol].dst,
        ):
            start_time = packet.time
            list_of_data.append(data_dict)
            if len(list_of_data) >= limit_packets:
                break

    dframe = pandas.DataFrame(list_of_data)
    if dframe.size > 0:
        dframe["dir"] = dframe.sport < dframe.dport
        dframe["port"] = numpy.where(dframe.dir, dframe.sport, dframe.dport)
        dframe.drop(columns=["sport", "dport"], inplace=True)
        dframe = dframe[
            ["ts", "ttl", "len", "proto", "tcp_flags", "window", "dir", "port"]
        ]

    return dframe


def ips_from_pcap(packets):
    """Extract IP and IPv6 addresses from given list of packets."""
    ips_pcap = set()
    for packet in packets:
        network_protocol = None
        if packet.haslayer(IP):
            network_protocol = IP
        elif packet.haslayer(IPv6):
            network_protocol = IPv6
        if network_protocol:
            ips_pcap.add(packet[network_protocol].src)
            ips_pcap.add(packet[network_protocol].dst)
    return ips_pcap


def tcp_dummies(data):
    """Convert categorical variables into indicator variables."""
    cats = ["PA", "A", "S", "SA", "FA", "FPA", "RA", "R", "SEC", "SAE", "AC", "PAC"]
    return (
        pandas.get_dummies(data, drop_first=True)
        .T.reindex(cats)
        .T.fillna(0)
        .astype("int8")
    )


def proto_dummies(data):
    """Convert categorical variables into indicator variables."""
    cats = [0, 1, 2, 6, 17, 58]
    return (
        pandas.get_dummies(data, drop_first=True)
        .T.reindex(cats)
        .T.fillna(0)
        .astype("int8")
    )


def prepare_data(data):
    """Prepare data frame for classification."""
    data = pandas.concat([data, tcp_dummies(data["tcp_flags"])], axis=1, sort=False)
    data = pandas.concat([data, proto_dummies(data["proto"])], axis=1, sort=False)
    data.drop(["tcp_flags", "proto"], axis=1, inplace=True)
    data["ts"] = data["ts"].astype("float64")
    return data


def normalizator(net_data):
    """Normalize numeric parameters."""
    # net_data["proto"] = (net_data.proto == 17) * 1.0
    net_data["dir"] = net_data.dir * 1.0
    net_data["port"] = (net_data.port - 32768.0) / 32768.0
    net_data["window"] = (net_data.window - 32768.0) / 32768.0
    net_data["ttl"] = (net_data.ttl - 128.0) / 128.0
    net_data["len"] = (net_data.len - 256.0) / 256.0
    return net_data


def generate_from_data_step_1(data, seq_length):
    """Prepare array for classification."""
    data["ts"] = data["ts"].astype("float64")
    data["dir"] = data["dir"].astype("int8")
    array = numpy.array([])
    if len(data) <= seq_length:
        array = numpy.array(data)
        array = numpy.append(
            array, numpy.zeros([seq_length - array.shape[0], array.shape[1]])
        )
    else:
        for i in range(len(data) - seq_length):
            array = numpy.append(array, numpy.array(data[i : i + seq_length]))
    return array


def predict_lstm(data):
    """Perform prediction using trained model."""
    data = generate_from_data_step_1(normalizator(prepare_data(data)), 10).reshape(
        -1, 10, 24
    )
    try:
        model = load_model(
            os.path.dirname(__file__) + "/identification_models/LSTM.hdf5"
        )
    except ValueError as exc:
        raise CotopaxiException from exc(
            "[!] Cannot load machine learning classifier!"
            "    This may be caused by incompatible version of tensorflow"
            "    (please install tensorflow version 2.2.0)!"
        )
    result = numpy.argmax(model.predict(data), axis=-1)
    unique, counts = numpy.unique(result, return_counts=True)
    devices = list()
    for unit in unique:
        devices.append(labels[unit])
    result_dict = dict(zip(devices, counts))
    result_dict = sorted(result_dict.items(), key=lambda x: x[1], reverse=True)
    result_class = labels[numpy.argmax(numpy.bincount(result))]
    return result_class, result_dict, counts.sum()


def classify_device(
    packets,
    ip_addr,
    show_class=True,
    show_probability=True,
    min_packets=3,
    max_packets=1000,
):
    """Classify device based on provided network traffic."""
    data = df_from_scapy(packets, ip_addr, limit_packets=max_packets)
    if data is None:
        print(
            f"[!] Packets with IP {ip_addr} were not found in the provided data capture!\n"
            f"[!] Classification stopped for IP {ip_addr}!"
        )
        return UNKNOWN_DEVICE_LABEL
    print(f"[!] Found {len(data)} packets to or from this IP")
    if len(data) < min_packets:
        print(
            f"[!] Not enough packets with IP {ip_addr} in the provided data capture!\n"
            f"[!] Classification stopped for IP {ip_addr}!"
        )
        return UNKNOWN_DEVICE_LABEL

    result_class, result_dict, sum_counts = predict_lstm(data)

    if show_class:
        print(f"[*]   Device was classified as:\n         {result_class}")

    if show_probability:
        print("[*]   Results of device identification:")
        for key, value in result_dict:
            print(f"           {key:>20}: {100*value/sum_counts:.2f}%")
    return result_class


def load_packets(pcap_filename, limit_packets=1000):
    """Load packets from provided pcap file."""
    start_time = time.time()
    packets = []
    try:
        if os.path.getsize(pcap_filename) > 100 * 2 ** 20:
            print(
                "[!] Provided pcap file is bigger than 100MB, so loading can take a while!\n"
                "[!] You can interrupt loading at any time using CTRL+C and classification "
                "will continue using already loaded packets."
            )
        reader = PcapReader(pcap_filename)  # pylint: disable=no-value-for-parameter
        for packet in reader:
            if len(packets) >= limit_packets:
                break
            packets.append(packet)
            if len(packets) % 10000 == 9999:
                load_time = time.time() - start_time
                print(
                    f"    Loaded first {len(packets)+1} packets (in {load_time:.2f} sec)..."
                )
    except KeyboardInterrupt:
        pass
    except (IOError, Scapy_Exception, ValueError) as exc:
        raise CotopaxiException from exc(
            "[!] Cannot load network packets from the provided file "
            "(please make sure it is in PCAP or PCAPNG format)!"
        )
    load_time = time.time() - start_time
    print(
        f"[.] Loaded {len(packets)} packets from the provided file (in {load_time:.2f} sec)"
    )
    return packets


def main(args):
    """Start device identification based on command line parameters."""
    if sys.version_info[0] < 3:
        raise Exception("This tool must be run using Python 3!")
    parser = argparse.ArgumentParser(
        description="Tool for classifying IoT devices based on captured network traffic"
    )
    parser = argparser_add_verbose(parser)
    parser.add_argument(
        "pcap",
        help=(
            "Packet capture file (in PCAP or PCAPNG format) "
            "with recorded traffic for device identification"
        ),
    )
    parser.add_argument(
        "--min",
        default=3,
        help="minimum number of packets to classify device "
        "(devices with smaller number will not be classified) (default: 3)",
    )
    parser.add_argument(
        "--max",
        default=1000,
        help="maximum number of packets used to classify device (default: 1000)",
    )
    parser.add_argument("--ip", "-I", help="use IP filter to identify device")
    parser.add_argument(
        "-S",
        "--short",
        dest="short_result",
        help="display only short result of classification",
        action="store_true",
    )

    options = parser.parse_args(args)
    test_name = "device identification"

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
            classify_device(
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
