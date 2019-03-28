# -*- coding: utf-8 -*-
"""Tool for checking availability of specified url on server at given IP and port ranges."""
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
import random
from .coap_utils import coap_check_url
from .common_utils import prepare_names, CotopaxiTester, print_verbose, Protocol
from .mdns_utils import mdns_query


def perform_resource_listing_coap(test_params, tuple_url_methods):
    """Checks whether listed urls/methods are available on CoAP server."""

    url_list, methods = tuple_url_methods
    for method in methods:
        url_not_existing = 'not existing' + 3 * str(random.randint(0, 32768))
        coap_code_not_existing = coap_check_url(test_params, method, url_not_existing)
        print_verbose(test_params, "CoAP server responds with code : {} "
                      .format(coap_code_not_existing) +
                      "for not existing URLs")
        for url in url_list:
            coap_check_result = coap_check_url(test_params, method, url)
            if coap_check_result == coap_code_not_existing:
                test_params.test_stats.inactive_endpoints[Protocol.CoAP].append(
                    "{}:{}/{}".format(test_params.dst_endpoint.ip_addr,
                                      test_params.dst_endpoint.port,
                                      url))
                print("[-] Url |{}| is not available on server {}:{} "
                      "for method {}".format(url,
                                             test_params.dst_endpoint.ip_addr,
                                             test_params.dst_endpoint.port, method))
            else:
                coap_return_code = coap_check_result
                test_params.test_stats.active_endpoints[Protocol.CoAP].append(
                    "{}:{}/{}".format(test_params.dst_endpoint.ip_addr,
                                      test_params.dst_endpoint.port,
                                      url))
                print("[+] Url |{}| received code |{}| on server {}:{} "
                      "for method {}".format(url, coap_return_code,
                                             test_params.dst_endpoint.ip_addr,
                                             test_params.dst_endpoint.port, method))


def perform_resource_listing_mdns(test_params, list_services):
    """Checks whether listed mDNS services are available on server."""
    for query in list_services:
        mdns_query(test_params, query)


def main(args):
    """Lists resources on remote service based on command line parameters"""

    tester = CotopaxiTester(check_ignore_ping=True, show_disclaimer=False)
    tester.argparser.add_argument('names_filepath', action='store', type=str,
                                  help="path to file with list of names "
                                       "(URLs for CoAP or services for mDNS) to be tested"
                                       " (each name in separated line)")
    tester.argparser.add_argument('--method', '-M', action='store',
                                  choices=('GET', 'POST', 'PUT', 'DELETE', 'ALL'),
                                  default='GET', nargs='+',
                                  help="methods to be tested (ALL includes all supported methods)")
    options = tester.parse_args(args)
    test_params = tester.get_test_params()
    if test_params.protocol == Protocol.CoAP:
        if options.method == ['ALL']:
            list_methods = ['GET', 'POST', 'PUT', 'DELETE']
        elif isinstance(options.method, list):
            list_methods = options.method
        else:
            list_methods = [options.method]

        print_verbose(test_params, "names_filepath: {}".format(options.names_filepath))
        print_verbose(test_params, "methods: {}".format(options.method))
        list_urls = prepare_names(options.names_filepath)
        print_verbose(test_params, list_urls)
        print_verbose(test_params, list_methods)
        tester.perform_testing("resource listing",
                               perform_resource_listing_coap,
                               (list_urls, list_methods))
    elif test_params.protocol == Protocol.mDNS:
        if options.method != 'GET':
            print("Methods are not supported for mDNS protocol!")
        list_services = prepare_names(options.names_filepath)
        print_verbose(test_params, list_services)
        tester.perform_testing("resource listing", perform_resource_listing_mdns, list_services)
    else:
        print("Please provide one of supported protocols (CoAP or mDNS)!")


if __name__ == "__main__":
    main(sys.argv[1:])
