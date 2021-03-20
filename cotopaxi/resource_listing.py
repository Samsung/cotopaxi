# -*- coding: utf-8 -*-
"""Tool for checking availability of specified url on server at given IP and port ranges."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#   Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#      Authors: Jakub Botwicz, Michał Radwański
#
#   This file is part of Cotopaxi.
#
#   Cotopaxi is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   Cotopaxi is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Cotopaxi.  If not, see <http://www.gnu.org/licenses/>.

import random
import sys

from .coap_utils import coap_check_url
from .common_utils import (
    Protocol,
    prepare_names,
    print_verbose,
    ssdp_send_query,
    tcp_sr1,
)
from .cotopaxi_tester import CotopaxiTester
from .mdns_utils import mdns_query
from .ssdp_utils import SSDP_MULTICAST_IPV4, SSDP_QUERY
from .rtsp_utils import build_rtsp_query


def perform_resource_listing_coap(test_params, tuple_url_methods):
    """Check whether listed urls/methods are available on CoAP server."""

    def check_method_and_url(method, url):
        """Check method and URL in CoAP response."""
        coap_check_result = coap_check_url(test_params, method, url)

        ip_port_and_url = "{}:{}/{}".format(
            test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port, url
        )

        if coap_check_result == coap_code_not_existing:
            test_params.test_stats.inactive_endpoints[Protocol.CoAP].append(
                ip_port_and_url
            )
            print(
                "[-] Url |{}| is not available on server {}:{} "
                "for method {}".format(
                    url.decode("ascii"),
                    test_params.dst_endpoint.ip_addr,
                    test_params.dst_endpoint.port,
                    method,
                )
            )
        else:
            coap_return_code = coap_check_result
            test_params.test_stats.active_endpoints[Protocol.CoAP].append(
                ip_port_and_url
            )
            print(
                "[+] Url |{}| received code |{}| on server {}:{} "
                "for method {}".format(
                    url.decode("ascii"),
                    coap_return_code,
                    test_params.dst_endpoint.ip_addr,
                    test_params.dst_endpoint.port,
                    method,
                )
            )

    url_list, methods = tuple_url_methods
    for method in methods:
        url_not_existing = "not existing" + 3 * str(random.randrange(2 ** 15))  # nosec
        coap_code_not_existing = coap_check_url(test_params, method, url_not_existing)
        print_verbose(
            test_params,
            "CoAP server responds with code : {} ".format(coap_code_not_existing)
            + "for not existing URLs",
        )
        for url in url_list:
            check_method_and_url(method, url)


def perform_resource_listing_mdns(test_params, list_services):
    """Check whether listed mDNS services are available on server."""
    for service_name in list_services:
        ip_port_and_url = "{}:{}/{}".format(
            test_params.dst_endpoint.ip_addr,
            test_params.dst_endpoint.port,
            service_name,
        )
        response = mdns_query(test_params, service_name)
        if response and service_name in response:
            test_params.test_stats.active_endpoints[Protocol.mDNS].append(
                ip_port_and_url
            )
        else:
            test_params.test_stats.inactive_endpoints[Protocol.mDNS].append(
                ip_port_and_url
            )


def perform_resource_listing_ssdp(test_params, list_services):
    """Check whether listed SSDP services are available on server."""
    for service_name in list_services:
        query = SSDP_QUERY.format(SSDP_MULTICAST_IPV4, service_name)
        response = ssdp_send_query(test_params, query)

        ip_port_and_url = "{}:{}/{}".format(
            test_params.dst_endpoint.ip_addr,
            test_params.dst_endpoint.port,
            service_name,
        )

        if response and service_name in response and "200 OK" in response:
            test_params.test_stats.active_endpoints[Protocol.SSDP].append(
                ip_port_and_url
            )
        else:
            test_params.test_stats.inactive_endpoints[Protocol.SSDP].append(
                ip_port_and_url
            )


def perform_resource_listing_rtsp(test_params, list_streams):
    """Check whether listed RTSP streams are available on server."""
    for stream_name in list_streams:
        print_verbose(test_params, "Testing stream: {}".format(stream_name))
        query = build_rtsp_query(test_params, "DESCRIBE", stream_name)
        print_verbose(
            test_params, "Prepared request: \n=\n{}\n=\n".format(query.strip())
        )
        response = tcp_sr1(test_params, query)
        if response:
            print_verbose(
                test_params, "Received response: \n=\n{}\n=\n".format(response.strip())
            )
        ip_port_and_url = "{}:{}/{}".format(
            test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port, stream_name
        )

        if response and stream_name in response and "RTSP/1.0 200 OK" in response:
            test_params.test_stats.active_endpoints[Protocol.RTSP].append(
                ip_port_and_url
            )
        else:
            test_params.test_stats.inactive_endpoints[Protocol.RTSP].append(
                ip_port_and_url
            )


def main(args):
    """List resources on remote service based on command line parameters."""
    tester = CotopaxiTester(
        test_name="resource listing",
        check_ignore_ping=True,
        show_disclaimer=False,
        use_generic_proto=False,
    )
    tester.argparser.add_argument(
        "names_filepath",
        action="store",
        type=str,
        help="path to file with list of names "
        "(URLs for CoAP or services for mDNS) to be tested"
        " (each name in separated line)",
    )
    tester.argparser.add_argument(
        "--method",
        "-M",
        action="store",
        choices=("GET", "POST", "PUT", "DELETE", "ALL"),
        default="GET",
        nargs="+",
        help="methods to be tested (ALL includes all supported methods)",
    )
    options = tester.parse_args(args)
    test_params = tester.test_params
    if test_params.protocol == Protocol.CoAP:
        if options.method == ["ALL"]:
            list_methods = ["GET", "POST", "PUT", "DELETE"]
        elif isinstance(options.method, list):
            list_methods = options.method
        else:
            list_methods = [options.method]

        print_verbose(test_params, "names_filepath: {}".format(options.names_filepath))
        print_verbose(test_params, "methods: {}".format(options.method))
        list_urls = prepare_names(options.names_filepath)
        print_verbose(test_params, list_urls)
        print_verbose(test_params, list_methods)
        tester.perform_testing(
            "resource listing", perform_resource_listing_coap, (list_urls, list_methods)
        )
    elif test_params.protocol == Protocol.SSDP:
        if options.method != "GET":
            print("Methods are not supported for SSDP protocol!")
        list_services = prepare_names(options.names_filepath)
        print_verbose(test_params, list_services)
        tester.perform_testing(
            "resource listing", perform_resource_listing_ssdp, list_services
        )
    elif test_params.protocol == Protocol.RTSP:
        list_services = prepare_names(options.names_filepath)
        print_verbose(test_params, list_services)
        tester.perform_testing(
            "resource listing", perform_resource_listing_rtsp, list_services
        )
    elif test_params.protocol == Protocol.mDNS:
        if options.method != "GET":
            print("Methods are not supported for mDNS protocol!")
        list_services = prepare_names(options.names_filepath)
        print_verbose(test_params, list_services)
        tester.perform_testing(
            "resource listing", perform_resource_listing_mdns, list_services
        )
    else:
        print("Please provide one of supported protocols (CoAP, mDNS or SSDP)!")


if __name__ == "__main__":
    main(sys.argv[1:])
