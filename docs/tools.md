# Tools

**cotopaxi.service_ping**

Tool for checking availability of network endpoints at given IP and port ranges
```
usage: python -m cotopaxi.service_ping [-h] [--retries RETRIES] [--timeout TIMEOUT]
                       [--verbose]
                       [--protocol {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                       [--src-ip SRC_IP] [--src-port SRC_PORT]
                       dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

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
  --protocol {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
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
usage: python -m cotopaxi.server_fingerprinter [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose] [--protocol {CoAP,DTLS}]
                               [--src-ip SRC_IP] [--src-port SRC_PORT]
                               [--ignore-ping-check]
                               dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

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

**cotopaxi.device_identification**

Tool for passive identification of IoT devices using captured network traffic

Currently supported devices:
* Amazon Cloudcam
* Amazon Echo Dot
* Amazon Echo Plus
* Amazon Echo Spot
* Amazon Fire TV
* Amcrest Camera
* Anova Sousvide
* Apple TV
* Blink Camera
* Blink Security Hub
* Bosiwo Camera
* D-Llink Mov Sensor
* Flux Bulb
* GE Microwave
* Google Home
* Google Home Mini
* Harman Kardon Allure
* Harman Kardon Invoke
* Honeywell Thermostat
* Insteon Hub
* Lefun Cam
* LG Smart TV
* Luohe Cam
* Magichome Strip
* Microseven Camera
* Nest Thermostat
* Netatmo Weather Station
* Osram Lightify Hub
* Philips Hue (Lightbulb)
* Philips Hue Hub
* Ring Doorbell
* Roku TV
* Samsung Fridge
* Samsung Dryer
* Samsung SmartThings Hub
* Samsung SmartTV
* Samsung Washer
* Sengled Smart Hub
* Smarter Brewer
* Smarter Coffee Machine
* Smarter iKettle
* TP-Link Bulb
* TP-Link Smart Plug
* Wansview Camera
* WeMo Plug
* WiMaker Charger Camera
* Wink Hub 2
* Xiaomi Mi Cam 2
* Xiaomi Mi Robot Cleaner
* Xiaomi Mi Hub
* Xiaomi Mi Rice Cooker
* Xiaomi Mi Power Strip
* Yi Camera
* Zmodo Greet (doorbell)

```
usage: python -m cotopaxi.device_identification usage: [-h] [--verbose] [--min MIN] [--max MAX]
                                [--ip IP] [-S]
                                pcap

Tool for classifying IoT devices based on captured network traffic

positional arguments:
  pcap                  Packet capture file (in PCAP or PCAPNG format) with
                        recorded traffic for device identification

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -V, --debug, -D
                        turn on verbose/debug mode (more messages)
  --min MIN             minimum number of packets to classify device (devices
                        with smaller number will not be classified) (default: 3)
  --max MAX             maximum number of packets used to classify device
                        (default: 1000)
  --ip IP, -I IP        use IP filter to identify device
  -S, --short           display only short result of classification


```

-------------------------------------------------------------------------------

**cotopaxi.traffic_analyzer**

Tool for passive identification of network protocol using captured network traffic

Currently supported protocols:
* AMQP
* BGP
* CMP
* CoAP
* DHCP
* DLNA
* DNS
* DTLS
* EIGRP
* FTP
* GNUTELLA
* GRE
* H323
* HSRP
* HTTP
* HTCPCP
* IGMP
* IPP
* IPsec
* IRC
* KNX
* LLMNR
* mDNS
* MQTT
* MQTT-SN
* MSTP
* NTLM
* NTP
* OCSP
* OSPF
* QUIC
* RADIUS
* RIP
* RPC
* RTSP
* SIP
* SMB
* SMTP
* SNMP
* SSDP
* SSH
* TACACS
* TELNET
* TFTP
* TLS
* VRRP

```
usage: python -m cotopaxi.traffic analyzer usage: [-h] [--verbose] [--min MIN] [--max MAX]
                                [--ip IP] [-S]
                                pcap

Tool for classifying network protocols used in traffic flows

positional arguments:
  pcap                  Packet capture file (in PCAP or PCAPNG format) with
                        recorded traffic for network protocols identification

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -V, --debug, -D
                        turn on verbose/debug mode (more messages)
  --min MIN             minimum number of packets to classify
                        conversation(conversations with smaller number will
                        not be classified) (default: 3)
  --max MAX             maximum number of packets used to classify
                        conversation (default: 1000)
  --ip IP, -I IP        use IP filter to identify protocol
  -S, --short           display only short result of classification


```

-------------------------------------------------------------------------------

**cotopaxi.resource_listing**

Tool for checking availability of resource named url on server at given IP and port ranges.
Sample URL lists are available in the _urls_ directory

```
usage: python -m cotopaxi.resource_listing [-h] [--retries RETRIES] [--timeout TIMEOUT]
                           [--verbose] [--protocol {CoAP,HTTP,mDNS,RTSP,SSDP}]
                           [--src-ip SRC_IP] [--src-port SRC_PORT]
                           [--ignore-ping-check]
                           [--method {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...]]
                           dest_addr dest_port names_filepath

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

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
usage: python -m cotopaxi.protocol_fuzzer [-h] [--retries RETRIES] [--timeout TIMEOUT]
                          [--verbose]
                          [--protocol {CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                          [--hide-disclaimer] [--src-ip SRC_IP]
                          [--src-port SRC_PORT] [--ignore-ping-check]
                          [--corpus-dir CORPUS_DIR]
                          [--delay-after-crash DELAY_AFTER_CRASH]
                          dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

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
  --protocol {CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
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
usage: (sudo) python -m cotopaxi.client_proto_fuzzer [-h] [--server-ip SERVER_IP]
                              [--server-port SERVER_PORT] [--verbose]
                              [--protocol {CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                              [--corpus-dir CORPUS_DIR]

(sudo required for listening on ports below 1024)

optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,DTLS,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested
  --corpus-dir CORPUS_DIR, -C CORPUS_DIR
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)
```

-------------------------------------------------------------------------------

**cotopaxi.vulnerability_tester**

Tool for checking vulnerability of network endpoints at given IP and port ranges
```
usage: python -m cotopaxi.vulnerability_tester -h
usage: vulnerability_tester.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose]
                               [--protocol {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                               [--hide-disclaimer] [--src-ip SRC_IP]
                               [--src-port SRC_PORT] [--ignore-ping-check]
                               [--vuln {ALL,BEWARD_000,BOTAN_000,...} ...]]
                               [--cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]]
                               [--list]
                               dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

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
  --protocol {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
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
usage: (sudo) python -m cotopaxi.client_vuln_tester [-h] [--server-ip SERVER_IP]
                             [--server-port SERVER_PORT] [--verbose]
                             [--protocol {CoAP,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                             [--vuln {ALL,BEWARD_000,BOTAN_000,...} ...]]
                             [--cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]]
                             [--list]

(sudo required for listening on ports below 1024)
optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,HTCPCP,HTTP,HTTP2,gRPC,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
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
usage: sudo python -m cotopaxi.amplifier_detector [-h] [--port PORT] [--nr NR] [--verbose] dest_addr

positional arguments:
  dest_addr               destination IP address

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
usage: python -m cotopaxi.active_scanner [-h] [--retries RETRIES] [--timeout TIMEOUT]
                         [--verbose] [--protocol {DTLS}] [--src-ip SRC_IP]
                         [--src-port SRC_PORT] [--ignore-ping-check]
                         dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

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

