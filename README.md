# Interop Test Runner - ACN

The Interop Test Runner aims to automatically generate an interop matrix by running multiple **test cases** using different QUIC implementations.
Note, this runner is an adaptation of the original implementation.
Instead of relying on docker-compose and simulating a network, it executes the server and client from a testbed management host on testbed machines or locally.

The testbed mode is not important for you, but used by us to test your implementations on real hardware in later phases of the project.

## Requirements
The Interop Runner is written in Python 3. You'll need to install a few Python modules to run it. A virtual environment would be optimal, especially when installing it on a testbed management host. 

```bash
pip3 install -r requirements.txt
```

* The client is given URLs including a hostname. To be able to resolve this hostname, the /etc/hosts file has to be updated. The hostname is "server". The IP address has to be set to 127.0.0.1 in local mode.

- Optional: For several testcases which inspect packet traces you need to install development version of Wireshark (version 3.4.2 or newer). The installed version on your ACN VM already supports all tests. 



## Example Usage
### Run in testbed mode
After installing the requirements:
```bash
# Copy your implementations over and set the path to it in implementations.json

# List all command line arguments
python3 run.py --help

# Test a handshake 
python3 run.py -t handshake

# Run all tests
python3 run.py
```

## Building a QUIC endpoint

To include your QUIC implementations in the Interop Runner, three scripts are required:
* setup-env.sh
* run-client.sh
* run-server.sh

Typically, a test case will require a server to serve files from a directory, and a client to download files. Different test cases will specify the behavior to be tested. For example, the Retry test case expects  the server to use a Retry before accepting the connection from the client.
All configuration information from the test framework to your implementation is fed to the scripts run-client.sh and run-server.sh.
You can use them in your respective implementations as enviorenment variables or use the script to transform them into command line parameters.

The test case is passed into your Docker container using the `TESTCASE` environment variable. If your implementation doesn't support a test case, it MUST exit with status code 127. This will allow us to add new test cases in the future, and correctly report test failures und successes, even if some implementations have not yet implented support for this new test case.

After the transfer is completed, the client container is expected to exit with exit status 0. If an error occurred during the transfer, the client is expected to exit with exit status 1.
After completion of the test case, the Interop Runner will verify that the client downloaded the files it was expected to transfer, and that the file contents match. Additionally, for certain test cases, the Interop Runner will use the pcap of the transfer to verify that the implementations fulfilled the requirements of the test (for example, for the Retry test case, the pcap should show that a Retry packet was sent, and that the client used the Token provided in that packet).

### Server Variables
The following variables will be given to the server and should be supported by your implementation
| Var | Description |
| -------- | -------- |
| SSLKEYLOGFILE | The variable contains the path + name of the keylog file. The output is required to decrypt traces and verify tests. The file has to be in the [NSS Key Log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) |
| QLOGDIR | qlog results are not required but might help to debug your output. However they have a negativ impact on performance so you might want to deactivate it for some tests|
| LOGS | It contains the path to a directory the server can use for its general logs. These will be uploaded as part of the results artifact. |
| TESTCASE | The name of the test case. You have to make sure a random string can be handled by your implementation. |
| WWW | It contains the directory that will contain one or more randomly generated files. Your server implementation is expected to run on the given port 443 and serve files from this directory. |
| CERTS | The runner will create an X.509 certificate and chain to be used by the server during the handshake. The variable contains the path to a directory that contains a priv.key and cert.pem file. |
| IP | The IP the server has to listen on. |
| PORT | The port the server has to listen on |
| SERVERNAME | The servername a client might send using SNI. The name relates to the provided certificate and might be necessary for some QUIC implementations. |

### Client Variables
The following variables will be given to the server and should be supported by your implementation
| Var | Description |
| -------- | -------- |
| SSLKEYLOGFILE | The variable contains the path + name of the keylog file. The output is required to decrypt traces and verify tests. The file has to be in the [NSS Key Log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format). |
| QLOGDIR| qlog results are not required but might help to debug your output. However they have a negativ impact on performance so you might want to deactivate it for some tests |
| LOGS| It contains the path to a directory the client can use for its general logs. These will be uploaded as part of the results artifact. |
| TESTCASE | The name of the test case. You have to make sure a random string can be handled by your implementation. |
| DOWNLOADS| The directory is initially empty, and your client implementation is expected to store downloaded files into this directory. Served and downloaded files are compared to check the test. |
| REQUESTS | A space seperated list of requests a client should execute one by one. (e.g., https://server:4433/xyz) |

### implementations.json
The implementations.json file contains a simple json with an object for each implementation.
Implementations as simply represented as a named object with a path variable.
The path should point to the folder containing the three required scripts.
Scripsts themselves should be able to execute at any location. Paths inside scripts (e.g., to your binaries) should be relative to the script.

### ACN Example

We offer an example implementation on the ACN material [website](https://acn.net.in.tum.de/).
It supports all required tests and can be used to test your implementations.

### Logs

To facilitate debugging, the Interop Runner saves the log files to the logs directory.

Implementations that implement [qlog](https://github.com/quiclog/internet-drafts) should export the log files to the directory specified by the `QLOGDIR` environment variable.

## Test cases

The Interop Runner implements the following test cases. Unless noted otherwise, test cases use HTTP/3 for file transfers. More test cases will be added in the future, to test more protocol features. The name in parentheses is the value of the `TESTCASE` environment variable passed into your Docker container.

* **Handshake** (`handshake`):
The client requests a single file and the server should serve the file. The test
is successful if there is exactly one QUIC handshake and no retries within the
packet trace. Additionally, the downloaded file must be equal to the file served
by the server.

* **Transfer** (`transfer`):
The client needs to send multiple requests and download all files using a single
connection. All files have to match and only a single handshake should be visible
to pass the test.

* **Multi Handshake** (`multihandshake`):
The client needs to send multiple requests and download all files using new
connections for each request. All files have to match and for each file, a
handshake needs to be visible to pass the test.

* **Version Negotiation** (`versionnegotiation`):
Tests whether a server sends a valid version negotiation packet in response to
an unknown QUIC version number. The client should start a connection using an
unsupported version number (it can use a reserved version number to do so), and
has to abort the connection attempt when receiving the Version Negotiation packet.
Note, the provided ACN server implementation only supports QUICv1 and the ACN
client implementation only supports Draft 29 during the test.

* **ChaCha20** (`chacha20`):
In this test, client and server are expected to offer only
`TLS_CHACHA20_POLY1305_SHA256` as a cipher suite. The client then downloads the files.

* **Retry** (`retry`):
Tests that the server can generate a Retry, and that the client can act upon it
(i.e. use the Token provided in the Retry packet in the Initial packet). Only a
single handshake should be visible.

* **Resumption** (`resumption`):
Tests QUIC session resumption (**without** 0-RTT). The client is expected to establish
a connection and download the first file (first value in the REQUESTS variable).
The server is expected to provide the client with a session ticket that allows it
to resume the connection. After downloading the first file, the client has to close
the first connection, establish a resumed connection using the session ticket, and
use this connection to download the remaining file(s).

* **0-RTT** (`zerortt`):
Tests QUIC 0-RTT. The client is expected to establish a connection and download the
first file. The server is expected to provide the client with a session ticket that
allows the client to establish a 0-RTT connection on the next connection attempt.
After downloading the first file, the client has to close the first connection,
establish and request the remaining file(s) in 0-RTT.

* **Multiplexing** (`multiplexing`):
Tests whether the server is able to set an `initial_max_streams_bidi` value of < 11
during the handshake. The client has to download all files with a single connection.
