
# Cotopaxi

Set of tools for security testing of Internet of Things devices using protocols like: CoAP, DTLS, HTCPCP, mDNS, MQTT, SSDP.

## License:

Cotopaxi uses GNU General Public License, version 2:
https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

## Installation:

Simply clone code from git:
    https://github.com/Samsung/cotopaxi

## Requirements:

Currently Cotopaxi works only with Python 2.7.x, but future versions will work also with Python 3. 

If you have previous installation of scapy without scapy-ssl_tls, please remove it or use venv. 

Installation of main libraries:

1. scapy-ssl_tls (this will install also scapy in 2.4.2)
```
    pip install git+https://github.com/tintinweb/scapy-ssl_tls@ec5714d560c63ea2e0cce713cec54edc2bfa0833
```

Common problems:
* If you encounter error: `error: [Errno 2] No such file or directory: 'LICENSE'`, try repeating command - surprisingly it works.
* If you encounter error: `NameError: name 'os' is not defined` - add missing `import os` to `scapy/layers/ssl_tls.py`.

All other required packages can be installed using requirements.txt file:
```
    pip install -r cotopaxi/requirements.txt
```

Manual installation of other required packages:
```
    pip install dnslib IPy hexdump pyyaml psutil enum34 configparser
```


## Disclaimer

Cotopaxi toolkit is intended to be used only for authorized security testing!

Some tools (especially vulnerability tester and protocol fuzzer) can cause some devices or servers to stop acting in the intended way 
-- for example leading to crash or hang of tested entities or flooding with network traffic another entities.

Make sure you have permission from the owners of tested devices or servers before running these tools!
 
Make sure you check with your local laws before running these tools! 
  

## Tools in this package:

* service_ping
* server_fingerprinter
* resource_listing
* server_fingerprinter
* protocol_fuzzer (for fuzzing servers)
* client_proto_fuzzer (for fuzzing clients)
* vulnerability_tester (for testing servers)
* client_vuln_tester (for testing clients)
* amplifier_detector
* active_scanner

Protocols supported by different tools: 

Tool                 | AMQP  | CoAP  | DTLS  | HTCPCP |  mDNS | MQTT  | QUIC  | RTSP  | SSDP
---------------------|-------|-------|-------|-------|--------|-------|-------|-------|-----
service_ping         |       |&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|       |&#9745;|&#9745;
server_fingerprinter |       |&#9745;|&#9745;|        |       |       |       |       |
credential_cracker   |       |       |       |        |       |       |       |       |
resource_listing     |       |&#9745;|  N/A  |        |&#9745;|       |       |&#9745;|&#9745;
protocol_fuzzer      |       |&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|       |&#9745;|&#9745;
client_proto_fuzzer  |       |&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|       |&#9745;|&#9745;
vulnerability_tester |       |&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|       |&#9745;|&#9745;
client_vuln_tester   |       |&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|       |&#9745;|&#9745;
amplifier_detector   |       |&#9745;|&#9745;|  N/A   |&#9745;|  N/A  |       |  N/A  |&#9745;
active_scanner       |       |       |&#9745;|        |       |       |       |       |


**cotopaxi.service_ping**

Tool for checking availability of network endpoints at given IP and port ranges
```
usage: sudo python -m cotopaxi.service_ping [-h] [-v] [--protocol {UDP,TCP,CoAP,MQTT,DTLS,ALL}]
                       [--src-port SRC_PORT]
                       dest_ip dest_port

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {UDP,TCP,CoAP,mDNS,SSDP,MQTT,DTLS,ALL,HTCPCP}, -P {UDP,TCP,CoAP,mDNS,SSDP,MQTT,DTLS,ALL,HTCPCP}
                        protocol to be tested (UDP includes CoAP, DTLS, mDNS,
                        and SSDP, TCP includes CoAP, HTCPCP, and MQTT, ALL
                        includes all supported protocols)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
```
-------------------------------------------------------------------------------

**cotopaxi.server_fingerprinter**

Tool for software fingerprinting of network endpoints at given IP and port ranges

Currently supported servers:
* CoAP:
    * aiocoap,
    * CoAPthon,
    * FreeCoAP,
    * libcoap,
    * MicroCoAP,
    * Mongoose
    * Wakaama (formerly liblwm2m)
* DTLS:
    *  GnuTLS,
    *  Goldy,
    *  LibreSSL,
    *  MatrixSSL,
    *  mbed TLS,
    *  OpenSSL,
    *  TinyDTLS
```
usage: sudo python -m cotopaxi.server_fingerprinter [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose]
                               [--protocol {CoAP,DTLS}]
                               [--src-port SRC_PORT]
                               dest_ip dest_port

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,DTLS}, -P {CoAP,DTLS}
                        protocol to be tested
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
```

-------------------------------------------------------------------------------

**cotopaxi.resource_listing**

Tool for checking availability of resource named url on server at given IP and port ranges.
Sample URL lists are available in the _urls_ directory

```
usage: sudo python -m cotopaxi.resource_listing [-h] [-v] [--protocol {CoAP,ALL}]
                           [--method {GET,POST,PUT,DELETE,ALL}]
                           [--src-port SRC_PORT]
                           dest_ip dest_port url_filepath

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both
  url_filepath          path to file with list of URLs to be tested (each URL
                        in separated line)

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,mDNS,SSDP}, -P {CoAP,mDNS,SSDP,RTSP}
                        protocol to be tested
  --method {GET,POST,PUT,DELETE,ALL}, -M {GET,POST,PUT,DELETE,ALL}
                        methods to be tested (ALL includes all supported
                        methods)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
```
-------------------------------------------------------------------------------

**cotopaxi.protocol_fuzzer**

Black-box fuzzer for testing protocol servers

```
usage: sudo python -m cotopaxi.protocol_fuzzer 
                          [-h] [--retries RETRIES] [--timeout TIMEOUT]
                          [--verbose] [--protocol {CoAP,mDNS,MQTT,DTLS}]
                          [--src-ip SRC_IP] [--src-port SRC_PORT]
                          [--ignore-ping-check] [--corpus-dir CORPUS_DIR]
                          dest_ip dest_port

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}, -P {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}
                        protocol to be tested
  --hide-disclaimer, -HD
                        hides legal disclaimer (shown before starting
                        intrusive tools)
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
  --corpus-dir CORPUS_DIR, -C CORPUS_DIR
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)
  --delay-after-crash DELAY_AFTER_CRASH, -DAC DELAY_AFTER_CRASH
                        number of seconds that fuzzer will wait after crash
                        for respawning tested server

```

-------------------------------------------------------------------------------

**cotopaxi.client_proto_fuzzer**

Black-box fuzzer for testing protocol clients

```
usage: sudo client_proto_fuzzer.py [-h] [--server-ip SERVER_IP]
                              [--server-port SERVER_PORT]
                              [--protocol {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}]
                              [--verbose] [--corpus-dir CORPUS_DIR]

optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --protocol {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}, -P {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}
                        protocol to be tested
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --corpus-dir CORPUS_DIR, -C CORPUS_DIR
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)

```

-------------------------------------------------------------------------------

**cotopaxi.vulnerability_tester**

Tool for checking vulnerability of network endpoints at given IP and port ranges
```
usage: sudo python -m cotopaxi.vulnerability_tester [-h] [-v]
                               [--cve {ALL,CVE-2018-19417,...}]
                               [--list LIST] [--src-port SRC_PORT]
                               dest_ip dest_port

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --protocol {UDP,TCP,CoAP,mDNS,MQTT,DTLS,ALL}, -P {UDP,TCP,CoAP,mDNS,MQTT,DTLS,ALL}
                        protocol to be tested (UDP includes CoAP, mDNS and
                        DTLS, TCP includes CoAP and MQTT, ALL includes all
                        supported protocols)
  --hide-disclaimer, -HD
                        hides legal disclaimer (shown before starting
                        intrusive tools)
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --cve {ALL,CVE-2018-19417,...}
                        list of vulnerabilities to be tested (by CVE id)
  --vuln {ALL,BOTAN_000,COAPTHON3_000,...} 
                        list of vulnerabilities to be tested (by SOFT_NUM id)

  --list, -L            display lists of all vulnerabilities supported by this
                        tool with detailed description
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
```
-------------------------------------------------------------------------------

**cotopaxi.client_vuln_tester**

Tool for checking vulnerability of network clients connecting to server provided by this tool

```
usage: sudo client_vuln_tester.py [-h] [--server-ip SERVER_IP]
                             [--server-port SERVER_PORT]
                             [--protocol {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}]
                             [--verbose]
                             [--vuln {ALL,BOTAN_000,COAPTHON3_000,...} [{ALL,BOTAN_000,COAPTHON3_000,...} ...]]
                             [--cve {ALL,CVE-2017-12087,...} [{ALL,CVE-2017-12087,...} ...]]
                             [--list]

optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --protocol {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}, -P {CoAP,mDNS,MQTT,DTLS,SSDP,HTCPCP}
                        protocol to be tested
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --vuln {ALL,BOTAN_000,COAPTHON3_000,...} [{ALL,BOTAN_000,COAPTHON3_000,...} ...]
                        list of vulnerabilities to be tested (by SOFT_NUM id)
  --cve {ALL,CVE-2017-12087,CVE-2017-12130,...} [{ALL,CVE-2017-12087,CVE-2017-12130,...} ...]
                        list of vulnerabilities to be tested (by CVE id)
  --list, -L            display lists of all vulnerabilities supported by this
                        tool with detailed description

```

-------------------------------------------------------------------------------

**cotopaxi.amplifier_detector**

Tool for detection of network devices amplifying reflected traffic
by observing size of incoming and outgoing size of packets
```
usage: sudo python -m cotopaxi.amplifier_detector [-h] [--port PORT] [--nr NR] [--verbose] dest_ip

positional arguments:
  dest_ip               destination IP address

optional arguments:
  -h, --help            show this help message and exit
  --interval INTERVAL, -I INTERVAL
                        minimal interval in sec between displayed status
                        messages (default: 1 sec)
  --port PORT, --dest_port PORT, -P PORT
                        destination port
  --nr NR, -N NR        number of packets to be sniffed (default: 9999999)
  --verbose, -V, --debug, -D
                        turn on verbose/debug mode (more messages)

```

-------------------------------------------------------------------------------

**cotopaxi.active_scanner**

Tool for checking security properties of network endpoints at given IP and port ranges

```
usage: sudo python -m cotopaxi.active_scanner [-h] [--retries RETRIES] [--timeout TIMEOUT]
                         [--verbose] [--protocol {DTLS}] [--src-ip SRC_IP]
                         [--src-port SRC_PORT] [--ignore-ping-check]
                         dest_ip dest_port

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {DTLS}, -P {DTLS}
                        protocol to be tested
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)

```


-------------------------------------------------------------------------------

## Known issues / limitations

There are some known issues or limitations caused by using scapy as network library:

* testing services running on the same machine can results in issues occurred by not delivering some packets,
* multiple tools running against the same target can result in interference between them 
(packets may be indicated as a response to another request).


See more at:
https://scapy.readthedocs.io/en/latest/troubleshooting.html#

## Unit tests

To run all unit tests use (from directory upper than cotopaxi dir):
```
    sudo python -m unittest discover
```

Most of tests are performed against remote tests servers and require preparing test environment, 
providing settings in tests/test_config.ini and tests/test_servers.yaml.

