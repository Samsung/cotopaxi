To use Cotopaxi from Metasploit:

1. Install Cotopaxi for python3 on the user account you will be running Metasploit on

2. Download sources of Cotopaxi from the repository

3. Run following commands from the OS command line:
```
cd $COTOPAXI_PATH/cotopaxi/integrations/metasploit
sudo cp -r modules $METASPLOIT_PATH/metasploit-framework/embedded/framework/
```

4. Start msfconsole and run following commands from the Metasploit CLI:
```
reload_all
use cotopaxi
```
You should see a list of multiple Cotopaxi modules in the following branches:
* auxiliary
    * cotopaxi 
      * (all tools)
    * fuzzers
        * amqp
            * client_fuzzer
            * server_fuzzer
        * coap
        * ...
    * scanner
        * amqp
          * ping
        * coap
        * ...
* exploits
    * iot
    * multi
        * amqp
          * client_vuln_tester
          * vulnerability_tester
        * coap
        * ...

5. Use the force
```
use auxiliary/scanner/coap/server_fingerprinter
setg RHOSTS 192.168.0.2
setg RPORTS 5683,5684,9999
setg PROTOCOLS CoAP
run
hosts
services
use auxiliary/cotopaxi/vulnerability_tester
setg RPORTS 80
setg PROTOCOLS HTTP
setg VULN_IDS TP-LINK_001
setg CVE_IDS CVE-2019-10028
run
vulns
```