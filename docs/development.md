# Development guide

## Source code quality

Before uploading your contribution using github Pull Request please check your code using tools listed below:

```
black -t py36 cotopaxi
black -t py36 tests

pydocstyle cotopaxi

python -m pylint cotopaxi --rcfile=.pylintrc
python -m pylint tests --rcfile=tests/.pylintrc

bandit -r cotopaxi
```

## Tests

To run all tests (unit tests, functional tests) with unittest use (from upper cotopaxi dir):
```
    sudo python -m unittest discover -v
```

To run all tests using unittest with coverage analysis run (from upper cotopaxi dir):
```
    sudo coverage run --source cotopaxi -m unittest discover
    coverage html
    firefox htmlcov/index.html
```

To run all tests using pytest with coverage analysis and branch analysis run (from upper cotopaxi dir):

```
    sudo python2.7 -m coverage run --source cotopaxi --branch -m pytest -v
    sudo python2.7 -m coverage html
    firefox htmlcov/index.html

    sudo python3 -m coverage run --source cotopaxi --branch -m pytest -v
    sudo python3 -m coverage html
    firefox htmlcov/index.html
```

To run tests for one of tools run (from upper cotopaxi dir):
```
    python -m tests.test_active_scanner
    sudo python -m tests.test_amplifier_detector
    python -m tests.test_client_proto_fuzzer
    python -m tests.test_device_identification
    python -m tests.test_traffic_analyzer
    python -m tests.test_protocol_fuzzer
    sudo python -m tests.test_resource_listing
    python -m tests.test_server_fingerprinter
    python -m tests.test_service_ping
    python -m tests.test_vulnerability_tester
```

Most of the tests are performed against remote tests servers and require preparing test environment, 
providing settings in tests/test_config.ini and tests/test_servers.yaml.

