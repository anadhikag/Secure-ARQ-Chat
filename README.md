# Secure Channel-Based Communication System using Stop-and-Wait ARQ

## Overview

This project implements a **secure, command-line–based communication system** that demonstrates core **Computer Networks concepts** such as framing, error detection, flow control, and reliable data transfer.

Clients can **create or join logical communication channels** identified by a **6-digit hexadecimal Channel ID**. Messages exchanged within a channel are **end-to-end encrypted**, while reliability is ensured using a **custom Stop-and-Wait ARQ protocol** implemented at the application level over UDP.

The relay server functions purely as a **packet forwarder** and **never decrypts message payloads**, ensuring true end-to-end encryption.

## System Architecture

Client A <----> Relay Server <----> Client B
(Encrypted, framed application-level packets)


### Server
- Maintains Channel ID → Client mappings
- Relays frames to appropriate channel members
- Simulates network conditions (packet loss)
- Does **not** decrypt messages

### Client
- Creates or joins channels
- Encrypts and decrypts messages
- Implements:
  - Framing
  - CRC-based error detection
  - Sequencing
  - Stop-and-Wait ARQ
- Handles ACKs, timeouts, and retransmissions

---

## Channel Management

- Each channel has a **6-digit hexadecimal ID (24 bits)**
- Maximum possible channels: 16⁶ ≈ 16.7 million
- Channel IDs act as **logical addresses and session identifiers**

### Commands
- `CREATE` → Create a new channel
- `JOIN <ChannelID>` → Join an existing channel

---

## Frame Format

All communication occurs using **frames**, not raw messages.

+-----------+--------+----------+---------+
| ChannelID | Type | Seq No | Payload | CRC |
+-----------+--------+----------+---------+


### Fields
- **ChannelID (3 bytes)**: Logical channel identifier
- **Type (1 byte)**: DATA, ACK, JOIN, CREATE
- **Sequence Number (4 bytes)**: For ordering and reliability
- **Payload**: Encrypted message data
- **CRC (2 bytes)**: Error detection using CRC-16

---

## Error Detection

- CRC is calculated on the payload
- Receiver recomputes CRC
- Frames with mismatched CRC are discarded
- Missing ACK triggers retransmission

This models **reliable communication over a noisy channel**.

---

## Reliability & Flow Control

### Stop-and-Wait ARQ
- Sender transmits one frame at a time
- Waits for ACK before sending the next frame
- Timeout triggers retransmission

This protocol ensures:
- Reliable delivery
- In-order reception
- Flow control

---

## End-to-End Encryption

- Encryption and decryption occur **only at the clients**
- Server relays encrypted frames without inspecting payloads
- A lightweight symmetric cipher is used to demonstrate:
  - Encryption placement in the protocol stack
  - Secure communication over untrusted networks

Encryption Flow:
Plaintext → Encrypt → Frame → CRC → Send


---

## Network Simulation

The server can simulate:
- Packet loss (configurable at runtime)

This allows evaluation of:
- ARQ behavior
- Retransmissions
- Protocol robustness

---

## Command-Line Interface

The project is entirely **CMD-based** to clearly observe protocol behavior.


---

## Technologies Used

- **Language:** Python
- **Networking:** UDP sockets
- **Concurrency:** Threading
- **Error Detection:** CRC-16
- **Encryption:** Symmetric XOR-based cipher (demonstration purpose)

---

## Computer Networks Concepts Demonstrated

- OSI Layered Architecture
- Framing and Data Link Layer design
- Error detection using CRC
- Stop-and-Wait ARQ
- Flow control and sequencing
- Logical addressing and session management
- End-to-end encrypted communication

---

## How to Run

### Start the Server
python main.py server

### Start a Client
python main.py


Run multiple clients in separate terminals to test communication.

---

## Conclusion

This project demonstrates how **reliable and secure communication** can be achieved over an **unreliable network** using fundamental Computer Networks principles. By reimplementing Data Link Layer mechanisms at the application level, the system provides clear insight into protocol behavior and network reliability techniques.
