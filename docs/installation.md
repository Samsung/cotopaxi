# Installation guide

## Installation using pip:

To install minimal Cotopaxi version (without Machine Learning and development tools): 

```
pip install cotopaxi
```

Minimal version + Machine Learning libraries (numpy, pandas, sklearn, xgboost):
```
pip install cotopaxi[ml]
```

Minimal version + development tools:
```
pip install cotopaxi[dev]
```

Almost complete installation (without scapy-ssl_tls):
```
pip install cotopaxi[all]
```

## Installation from source:

1. Clone code from git:
``` 
git clone https://github.com/Samsung/cotopaxi 
```
2. Enter cotopaxi directory
```
cd cotopaxi 
```
3. Run installer:
```
python setup.py install
```

Optional:

4. Install extras

(ml - Machine Learning tools, dev - development tools, all - all of the above)
```
pip install -e .[ml]
```

5. Install scapy-ssl_tls (in case of any problems with scapy and scapy-ssl_tls see section below)

Installation of scapy-ssl_tls is OPTIONAL - required only if you want to test endpoints using DTLS protocol. 

For Python 2.7:
 
(this will install also scapy in 2.4.2)
```
    pip install git+https://github.com/tintinweb/scapy-ssl_tls@ec5714d560c63ea2e0cce713cec54edc2bfa0833
```
For Python 3.6-3.8:
```
    git clone https://github.com/kalidasya/scapy-ssl_tls.git
    cd scapy-ssl_tls
    git checkout py3_update
    python3 setup.py install
```

## Requirements:

Currently Cotopaxi works with Python 2.7.* and with Python 3.6-3.8 (some dependencies like tensorflow do not work on 3.9). 

Installation of required libraries:

### scapy-ssl_tls 

For Python 2.7:
 
(this will install also scapy in 2.4.2)
```
    pip install git+https://github.com/tintinweb/scapy-ssl_tls@ec5714d560c63ea2e0cce713cec54edc2bfa0833
```
Common problems:
* If you encounter error: `error: [Errno 2] No such file or directory: 'LICENSE'`, try repeating command - surprisingly it works.
* If you encounter error: `NameError: name 'os' is not defined` - add missing `import os` to `scapy/layers/ssl_tls.py`.

### Manual installation of other requirements:

For Python 2.7:

```
sudo python2.7 -m pip install -r requirements_python2.txt 
```

For Python 3.6-3.8:

(for installing MINIMAL set of libraries EXCLUDING large Machine Learning libraries (pandas, sklearn, tensorflow, xgboost) required for device_identification and traffic_analyzer)

```
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install -r requirements_minimal.txt 
```

(for installing FULL set of libraries INCLUDING large Machine Learning libraries (pandas, sklearn, tensorflow, xgboost) required for device_identification and traffic_analyzer)
```
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install -r requirements.txt 
```

All required packages for developement of Cotopaxi (including libraries for unit tests) can be installed using requirements_devel.txt file:
```
    pip install -r cotopaxi/requirements_devel.txt
    pre-commit install
```