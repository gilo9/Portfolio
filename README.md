# CO3099Assignment

## Overview

This repository contains the coursework submission for the CO3099 module (University of Leicester). The project is implemented in Java and demonstrates practical skills in network programming, cryptography, file I/O, and secure client-server messaging.

---

## Table of Contents

- [Features](#features)
- [Skills & Technologies](#skills--technologies)
- [System Architecture](#system-architecture)
- [Sample Workflows](#sample-workflows)
- [Professional Development](#professional-development)
- [License & Authorship](#license--authorship)

---

## Features

- **Secure Client-Server Messaging**  
  - Implements a client and server exchanging encrypted and signed messages over a network socket.
  - Utilizes RSA and DES for encryption/decryption, and digital signatures for message verification.
  - Handles message delivery with signature verification and optional reply.

- **Key Management & Generation**  
  - Tools for generating RSA key pairs (`RSAKeyGen.java`).
  - Loads and manages public/private keys from files.

- **Symmetric & Asymmetric Encryption**  
  - Demonstrates DES key generation, message encryption/decryption (`encryption.java`).
  - Uses RSA for encrypting messages and verifying authenticity.

- **File I/O & Streams**  
  - Reads and writes messages and keys to disk.
  - Demonstrates Java's DataInputStream/DataOutputStream for binary communication (`streams.java`, `bytes.java`).

- **Modular Structure**  
  - Organized codebase in `src/main/java/org/example` for maintainability and clarity.

---

## Skills & Technologies

- **Programming Language**: Java
- **Networking**: TCP sockets, client-server architecture
- **Cryptography**: RSA, DES, digital signatures
- **File I/O**: Streams, serialization, reading/writing binary data
- **Software Engineering**: Modular design, separation of concerns, secure coding practices
- **Version Control**: Git & GitHub

---

## System Architecture

- **Client (`Client.java`)**: Connects to server, authenticates, receives and verifies messages, sends encrypted and signed messages to other users.
- **Server (`Server.java`)**: Listens for incoming connections, manages user messages, decrypts and verifies them, delivers stored messages to users.
- **Key Utility (`Keys.java`, `RSAKeyGen.java`)**: Generates and loads RSA key pairs, manages keys for users and server.
- **Encryption Utility (`encryption.java`)**: Provides DES-based symmetric encryption/decryption for file-stored messages.
- **Supporting Utilities (`streams.java`, `bytes.java`)**: Demonstrates handling of bytes and file streams.

**Directory Structure:**
```
CO3099Assignment/
└── src/
    └── main/
        └── java/
            └── org/
                └── example/
                    ├── Client.java
                    ├── Server.java
                    ├── Keys.java
                    ├── RSAKeyGen.java
                    ├── encryption.java
                    ├── streams.java
                    ├── bytes.java
```

---

## Sample Workflows

1. **Generate RSA Keys**  
   *Run RSAKeyGen to generate key pairs for a user or server:*
   ```
   java org.example.RSAKeyGen alice
   ```
   *Creates `alice.pub` and `alice.prv`.*

2. **Start the Server**  
   *Start the server and listen for connections:*
   ```
   java org.example.Server <port>
   ```

3. **Start the Client**  
   *Connect client to server and authenticate:*
   ```
   java org.example.Client <host> <port> <userId>
   ```

4. **Send/Receive Secure Messages**  
   *Client sends encrypted/signed messages. Server decrypts, verifies, and delivers messages securely.*

5. **Symmetric Encryption Demo**  
   *Encrypt and decrypt messages using DES:*
   ```
   java org.example.encryption -e    # Encrypt mode
   java org.example.encryption -d    # Decrypt mode
   ```

---

## Professional Development

Working on this project evidences:

- Proficiency in Java network and security programming
- Understanding of cryptographic protocols (RSA, DES, digital signatures)
- Secure handling of messages and key management
- Modular software architecture and version control
- Practical experience in problem-solving and technical documentation

---

## License & Authorship

This project is a coursework submission for CO3099 at University of Leicester. All code is original unless stated otherwise.

**Author:** [gilo9](https://github.com/gilo9)  
**Module:** CO3099, University of Leicester

---

