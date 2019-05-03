
# Cotopaxi

Set of tools for security testing of Internet of Things devices using protocols like: CoAP, DTLS, mDNS, MQTT.

## License:

Cotopaxi uses GNU General Public License, version 2:
https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

## Installation:

Simply clone code from git:
    https://github.com/Samsung/cotopaxi

## Requirements:

Currently Cotopaxi works only with Python 2.7.x, but future versions will work also with Python 3. 

All required packages can be installed using requirements.txt file:
```
    cd cotopaxi
    pip install -r requirements.txt
```

Manual installation of dependencies:

1. scapy (latest development version)
```
    git clone https://github.com/secdev/scapy
    cd scapy
    sudo python setup.py install
```

(if you encounter error: "ImportError: No module named coap" - it means that older version of Scapy is used - check your installation, paths and in case the problem continues - remove the older version)

2. scapy-ssl_tls (latest development version)
```
    git clone https://github.com/tintinweb/scapy-ssl_tls.git
    cd scapy-ssl_tls
    sudo python setup.py install
```
(if you encounter error: "ImportError: No module named ssl_tls" - it means that older version of scapy-ssl_tls is used)

(if you encounter error: NameError: name 'os' is not defined - add missing 'import os' to scapy/layers/ssl_tls.py)

3. IPy
```
    sudo pip install IPy
```

4. hexdump
```
    sudo pip install hexdump
```

5. dnslib
```
    sudo pip install dnslib
```

6. pyyaml (only for preparing test environment)
```
    sudo pip install pyyaml
```

7. psutil (only for preparing test environment)
```
    sudo pip install psutil
```

## Disclaimer

Cotopaxi toolkit is intended to be used only for authorized security testing!

Some tools (especially vulnerability tester and protocol fuzzer) can cause some devices or servers to stop acting in the intended way 
-- for example leading to crash or hang of tested entities or flooding with network traffic another entities.

Make sure you have permission from the owners of tested devices or servers before running these tools!
 
Make sure you check with your local laws before running these tools! 
  

## Tools in this package:

**cotopaxi.service_ping**

Tool for checking availability of network service at given IP and port ranges
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
  --protocol {UDP,TCP,CoAP,MQTT,DTLS,ALL}, -P {UDP,TCP,CoAP,MQTT,DTLS,ALL}
                        protocol to be tested (UDP includes CoAP and DTLS, TCP
                        includes CoAP and MQTT, ALL includes all supported
                        protocols)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
```
-------------------------------------------------------------------------------

**cotopaxi.server_fingerprinter**

Tool for software fingerprinting of network servers at given IP and port ranges

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
* MQTT:
    * (work in progress)

```
usage: sudo python -m cotopaxi.server_fingerprinter [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose]
                               [--protocol {UDP,TCP,CoAP,MQTT,DTLS,ALL}]
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
  --protocol {UDP,TCP,CoAP,MQTT,DTLS,ALL}, -P {UDP,TCP,CoAP,MQTT,DTLS,ALL}
                        protocol to be tested (UDP includes CoAP and DTLS, TCP
                        includes CoAP and MQTT, ALL includes all supported
                        protocols)
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
  --protocol {CoAP,ALL}, -P {CoAP,ALL}
                        protocol to be tested (ALL includes all supported
                        protocols: CoAP)
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
  --protocol {CoAP,mDNS,MQTT,DTLS}, -P {CoAP,mDNS,MQTT,DTLS}
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
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)

```

-------------------------------------------------------------------------------

**cotopaxi.vulnerability_tester**

Tool for checking vulnerability of network service at given IP and port ranges
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

## Known issues / limitations

There are some known issues or limitations caused by using scapy as network library:

* testing services running on the same machine can results in issues occurred by not delivering some packets,
* multiple tools running against the same target can result in interference between them 
(packets may be indicated as a response to another request).


See more at:
https://scapy.readthedocs.io/en/latest/troubleshooting.html#


