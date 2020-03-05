
# Cotopaxi

Set of tools for security testing of Internet of Things devices using protocols: AMQP, CoAP, DTLS, HTCPCP, mDNS, MQTT, MQTT-SN, QUIC, RTSP, SSDP.

## License:

Cotopaxi uses GNU General Public License, version 2:
https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

## Installation:

1. Clone code from git:
``` 
git clone https://github.com/Samsung/cotopaxi 
```
2. Enter cotopaxi directory
```    
cd cotopaxi 
```
3. Install requirements (in case of any problems with scapy and scapy-ssl_tls see section below):
```
sudo pip install -r requirements.txt 
```
4. Run installer:
```
sudo python setup.py install
```

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

Tool                 | AMQP  | CoAP  | DTLS  | HTCPCP |  mDNS | MQTT  |MQTT-SN| QUIC  | RTSP  | SSDP
---------------------|-------|-------|-------|-------|--------|-------|-------|-------|-------|-----
service_ping         |&#9745;|&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|&#9745;|&#9745;|&#9745;|&#9745;
server_fingerprinter |       |&#9745;|&#9745;|        |       |       |       |       |
credential_cracker   |       |  N/A  |  N/A  |  N/A   |  N/A  |       |       |  N/A  |  N/A  |  N/A  
resource_listing     |       |&#9745;|  N/A  |        |&#9745;|       |       |       |&#9745;|&#9745;
protocol_fuzzer      |&#9745;|&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|&#9745;|&#9745;|&#9745;|&#9745;
client_proto_fuzzer  |&#9745;|&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|&#9745;|&#9745;|&#9745;|&#9745;
vulnerability_tester |&#9745;|&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|&#9745;|&#9745;|&#9745;|&#9745;
client_vuln_tester   |&#9745;|&#9745;|&#9745;|&#9745; |&#9745;|&#9745;|&#9745;|&#9745;|&#9745;|&#9745;
amplifier_detector   |  N/A  |&#9745;|&#9745;|  N/A   |&#9745;|  N/A  |&#9745;|&#9745;|  N/A  |&#9745;
active_scanner       |       |       |&#9745;|        |       |       |       |       |       |


**cotopaxi.service_ping**

Tool for checking availability of network endpoints at given IP and port ranges
```
usage: sudo python -m cotopaxi.service_ping.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                       [--verbose]
                       [--protocol {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}]
                       [--src-ip SRC_IP] [--src-port SRC_PORT]
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
  --protocol {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested (UDP includes all UDP-based
                        protocols, while TCP includes all TCP-based protocols,
                        ALL includes all supported protocols)
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
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
usage: sudo python -m cotopaxi.server_fingerprinter.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose] [--protocol {CoAP,DTLS}]
                               [--src-ip SRC_IP] [--src-port SRC_PORT]
                               [--ignore-ping-check]
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

**cotopaxi.resource_listing**

Tool for checking availability of resource named url on server at given IP and port ranges.
Sample URL lists are available in the _urls_ directory

```
usage: sudo python -m cotopaxi.resource_listing.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                           [--verbose] [--protocol {CoAP,HTTP,mDNS,RTSP,SSDP}]
                           [--src-ip SRC_IP] [--src-port SRC_PORT]
                           [--ignore-ping-check]
                           [--method {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...]]
                           dest_ip dest_port names_filepath

positional arguments:
  dest_ip               destination IP address or multiple IPs separated by
                        coma (e.g. '1.1.1.1,2.2.2.2') or given by CIDR netmask
                        (e.g. '10.0.0.0/22') or both
  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both
  names_filepath        path to file with list of names (URLs for CoAP or
                        services for mDNS) to be tested (each name in
                        separated line)

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,HTTP,mDNS,RTSP,SSDP}, -P {CoAP,HTTP,mDNS,RTSP,SSDP}
                        protocol to be tested
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
  --method {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...], -M {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...]
                        methods to be tested (ALL includes all supported
                        methods)

```
-------------------------------------------------------------------------------

**cotopaxi.protocol_fuzzer**

Black-box fuzzer for testing protocol servers

```
usage: sudo python -m cotopaxi.protocol_fuzzer.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                          [--verbose]
                          [--protocol {CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}]
                          [--hide-disclaimer] [--src-ip SRC_IP]
                          [--src-port SRC_PORT] [--ignore-ping-check]
                          [--corpus-dir CORPUS_DIR]
                          [--delay-after-crash DELAY_AFTER_CRASH]
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
  --protocol {CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}
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
usage: sudo python -m cotopaxi.client_proto_fuzzer.py [-h] [--server-ip SERVER_IP]
                              [--server-port SERVER_PORT] [--verbose]
                              [--protocol {CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}]
                              [--corpus-dir CORPUS_DIR]

optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,DTLS,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested
  --corpus-dir CORPUS_DIR, -C CORPUS_DIR
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)
```

-------------------------------------------------------------------------------

**cotopaxi.vulnerability_tester**

Tool for checking vulnerability of network endpoints at given IP and port ranges
```
usage: sudo python -m cotopaxi.cotopaxi.vulnerability_tester -h
usage: vulnerability_tester.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose]
                               [--protocol {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}]
                               [--hide-disclaimer] [--src-ip SRC_IP]
                               [--src-port SRC_PORT] [--ignore-ping-check]
                               [--vuln {ALL,BEWARD_000,BOTAN_000,...} ...]]
                               [--cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]]
                               [--list]
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
  --protocol {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested (UDP includes all UDP-based
                        protocols, while TCP includes all TCP-based protocols,
                        ALL includes all supported protocols)
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
  --vuln {ALL,BEWARD_000,BOTAN_000,...} ...]
                        list of vulnerabilities to be tested (by SOFT_NUM id)
  --cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]
                        list of vulnerabilities to be tested (by CVE id)
  --list, -L            display lists of all vulnerabilities supported by this
                        tool with detailed description

```
-------------------------------------------------------------------------------

**cotopaxi.client_vuln_tester**

Tool for checking vulnerability of network clients connecting to server provided by this tool

```
usage: sudo python -m cotopaxi.client_vuln_tester.py [-h] [--server-ip SERVER_IP]
                             [--server-port SERVER_PORT] [--verbose]
                             [--protocol {CoAP,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}]
                             [--vuln {ALL,BEWARD_000,BOTAN_000,...} ...]]
                             [--cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]]
                             [--list]

optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,HTCPCP,HTTP,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested
  --vuln {ALL,BEWARD_000,BOTAN_000,...} ...]
                        list of vulnerabilities to be tested (by SOFT_NUM id)
  --cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]
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

To run all unit tests use (from upper cotopaxi dir):
```
    sudo python -m unittest discover
```

To run all unit tests with coverage analysis use (from upper cotopaxi dir):
```
    sudo coverage run --source cotopaxi -m unittest discover
    coverage html
    firefox htmlcov/index.html
```

Most of tests are performed against remote tests servers and require preparing test environment, 
providing settings in tests/test_config.ini and tests/test_servers.yaml.

