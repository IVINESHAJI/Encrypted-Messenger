# Encrypted Chat Application

A **terminal-based end-to-end encrypted (E2EE)** messaging application written in Python. This project demonstrates secure, private, real-time communication using modern cryptographic standards — similar in concept to Signal or WhatsApp, but built for learning and customization.

---

## Features

- **Key Exchange with X25519 (ECDH)**  
  Securely derive a shared secret between two users using **Elliptic Curve Diffie-Hellman** over Curve25519.

- **Message Encryption with AES-GCM**  
  Messages are encrypted using **AES in Galois/Counter Mode**, providing both **confidentiality** and **integrity** in one pass.

- **Real-time Chat Over TCP Sockets**  
  Interactive terminal chat interface with **bi-directional communication** between two systems over a network (LAN or internet).

- **Perfect Forward Secrecy**  
  Shared AES keys are regenerated **for every session**, ensuring that past conversations remain secure even if future keys are compromised.

- **Tamper Detection & Message Integrity**  
  Messages that are altered or forged in transit are rejected using AES-GCM's authentication tag.

- **Clean CLI Structure & Modular Codebase**  
  Designed with readability in mind. Easy to extend with features like file transfer, message history, or user authentication.

---

## Requirements

Install dependencies:

```bash
pip install cryptography
