# Secure File Transfer using SSH Protocol
This project implements a client-server system for secure file transfer using the SSH (Secure Shell) protocol. The SSH protocol provides a secure channel between the client and server over which file transfer operations can be performed securely. The implementation utilizes the OpenSSL library to implement the SSH protocol and perform encryption and decryption tasks. The project was done as part of CSE543 -- Computer Security at the Pennsylvania State University -- University Park.


## Overview

This project implements a client-server system for secure file transfer using the SSH (Secure Shell) protocol. The implementation utilizes the OpenSSL library to implement the SSH protocol and perform encryption and decryption tasks.
Prerequisites

* OpenSSL library
* C/C++ compiler

## Usage
1. Creating Public and Private Keys

You need to generate public and private keys using OpenSSL. Run the following commands:
```
> bash

# Generate key pair - mykey.pem holds private key
> openssl genrsa -out mykey.pem 2048

# Extract public key in basic format - pubkey.pem is in PKCS#8 format
> openssl rsa -in mykey.pem -pubout -out pubkey.pem

# Convert public key to RSA format - rsapub.pem holds public key
> openssl rsa -pubin -in pubkey.pem -RSAPublicKey_out > rsapub.pem
```
2. Running the Client and Server
Server

Start the server program with the following command:
```
> bash

> cse543-p1-server <private-key-file> <public-key-file>
```
Replace <private-key-file> with the name of the file storing the server's private key, and <public-key-file> with the corresponding RSA format public key for the server.
Client
```
Start the client program with the following command:

> bash

> cse543-p1 <file-to-transfer> <server-ip-address>
```

Replace <file-to-transfer> with the file path name of the file to transfer from the client to the server, and <server-ip-address> with the IP address of the server host.
3. Perform the SSH Protocol

The client initiates the SSH protocol to produce a symmetric key shared by the client and server.
4. Transfer the File

The specified file will be sent encrypted and integrity-protected from the client to the server. The server stores the file in a directory called “shared” under its current directory.
5. Server Awaits Next Request

After the file transfer is complete, the client terminates, and the server awaits the next request from another client.

## Implementation Details

* The SSH protocol is implemented based on the specification described in the provided SSH.pdf document.
* OpenSSL library functions are used to perform encryption, decryption, and key exchange.
* Symmetric and asymmetric encryption techniques are employed to ensure secure communication.
* RSA encryption is used for key exchange between the client and server.
