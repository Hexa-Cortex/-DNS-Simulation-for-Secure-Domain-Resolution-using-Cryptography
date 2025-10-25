# SecureDNS - Cryptographic DNS Simulation System

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

A complete DNS simulation system implementing modern cryptographic techniques for secure domain resolution, including RSA-2048 digital signatures, AES-256-GCM encryption, and DNSSEC-like validation.

## 🌟 Features

- **🔐 Digital Signatures**: RSA-2048 signatures for DNS record authentication
- **🔒 Query Encryption**: AES-256-GCM encryption for private DNS queries
- **✅ DNSSEC Simulation**: Chain of trust verification
- **🛡️ Anti-Poisoning**: Cryptographic validation prevents cache poisoning
- **⚡ Multi-threaded**: Concurrent query handling with thread-safe operations
- **💻 CLI Interface**: Beautiful command-line interface with colored output
- **📊 Performance**: ~200-250 queries/second with <5ms overhead

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Security Features](#security-features)
- [Architecture](#architecture)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-dns-simulator.git
cd secure-dns-simulator

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
python -c "from src.crypto.signature import DNSRecordSigner; print('✓ Installation successful')"
```

## 🏃 Quick Start

### 1. Start the Server

```bash
python -m src.server
```

**Expected output:**
```
============================================================
  SecureDNS Server Started
============================================================
  Address: 0.0.0.0:5353
  Features: RSA Signatures + AES Encryption
  Press Ctrl+C to stop
============================================================

✓ Loaded 4 DNS records
```

### 2. Query a Domain (New Terminal)

```bash
python -m src.client query example.com
```

**Expected output:**
```
============================================================
✓ QUERY SUCCESSFUL
============================================================
Domain:       example.com
Type:         A
IP Address:   93.184.216.34
TTL:          3600 seconds
Signed:       ✓ Yes
Verified:     ✓ Valid
============================================================
```

### 3. Run Connectivity Tests

```bash
python -m src.client test
```

## 💻 Usage Examples

### Basic Queries

```bash
# Query A record
python -m src.client query example.com

# Query with different record type
python -m src.client query example.com --type A

# Query on custom port
python -m src.client query example.com --server localhost --port 5353
```

### Encrypted Queries

```bash
# Send encrypted DNS query
python -m src.client query example.com --encrypted
```

### Skip Signature Verification

```bash
# Query without verifying signature
python -m src.client query example.com --no-verify
```

### Server Options

```bash
# Start on default port (5353)
python -m src.server

# Start on custom port
python -m src.server --port 8053

# Start on specific host
python -m src.server --host 127.0.0.1 --port 5353
```

## 🔒 Security Features

### 1. Digital Signatures (RSA-2048)

Every DNS record is signed using RSA-2048 with PSS padding and SHA-256 hashing.

**Example:**
```python
from src.crypto.signature import DNSRecordSigner

signer = DNSRecordSigner()

# Create DNS record
record = {
    "domain": "example.com",
    "type": "A",
    "data": "93.184.216.34",
    "ttl": 3600
}

# Sign the record
signed_record = signer.sign_record(record)
print(f"Signature: {signed_record['signature'][:50]}...")

# Verify signature
is_valid = signer.verify_signature(signed_record)
print(f"Valid: {is_valid}")  # True

# Detect tampering
signed_record['record']['data'] = "192.0.2.1"
is_valid = signer.verify_signature(signed_record)
print(f"Valid after tampering: {is_valid}")  # False
```

**Benefits:**
- ✅ Authenticity - Verify records come from authorized sources
- ✅ Integrity - Detect any modifications to DNS records
- ✅ Non-repudiation - Cryptographic proof of record origin

### 2. Query Encryption (AES-256-GCM)

DNS queries can be encrypted using AES-256 in GCM mode for authenticated encryption.

**Example:**
```python
from src.crypto.encryption import QueryEncryptor

encryptor = QueryEncryptor()

# Encrypt query
encrypted = encryptor.encrypt_query("confidential.example.com", "A")
print(f"Encrypted: {encrypted['ciphertext'][:40]}...")

# Decrypt query
decrypted = encryptor.decrypt_query(encrypted)
print(f"Domain: {decrypted['domain']}")  # confidential.example.com
```

**Benefits:**
- 🔒 Confidentiality - Queries are hidden from eavesdroppers
- ✅ Authentication - GCM mode provides authentication tags
- 🛡️ Replay Protection - Nonce-based anti-replay mechanism

### 3. Cache Poisoning Prevention

All records are cryptographically validated before being cached or served:
- Signature verification before caching
- TTL enforcement with signed timestamps
- Integrity checks on cache retrieval
- Automatic rejection of tampered records

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────┐
│                     DNS Client                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │    Query     │  │   Encrypt    │  │    Verify    │ │
│  │   Builder    │→ │   (AES-256)  │→ │  Signature   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└────────────────────────┬────────────────────────────────┘
                         │ UDP/5353
                         ↓
┌─────────────────────────────────────────────────────────┐
│                   SecureDNS Server                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Decrypt    │→ │   Resolve    │→ │     Sign     │ │
│  │  (AES-256)   │  │   Record     │  │  (RSA-2048)  │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │         Signed DNS Records Database             │  │
│  │   example.com → 93.184.216.34 [SIGNED]         │  │
│  │   test.com → 192.168.1.100 [SIGNED]            │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Project Structure

```
secure-dns-simulator/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
│
├── src/
│   ├── __init__.py               # Package marker
│   ├── server.py                 # DNS server (~150 lines)
│   ├── client.py                 # CLI client (~150 lines)
│   │
│   └── crypto/
│       ├── __init__.py           # Package marker
│       ├── signature.py          # RSA-2048 signatures (~200 lines)
│       └── encryption.py         # AES-256-GCM encryption (~150 lines)
│
└── examples/
    └── demo.py                   # Interactive demo (optional)
```

### Components

**Server (`src/server.py`)**
- Multi-threaded UDP server
- Handles DNS queries on port 5353
- Signs all responses with RSA-2048
- Supports encrypted queries

**Client (`src/client.py`)**
- Command-line interface
- Supports standard and encrypted queries
- Automatic signature verification
- Pretty-printed output with colors

**Signature Module (`src/crypto/signature.py`)**
- RSA-2048 key generation
- Record signing with PSS padding
- Signature verification
- Public/private key export

**Encryption Module (`src/crypto/encryption.py`)**
- AES-256-GCM encryption
- PBKDF2 key derivation
- Query/response encryption
- Authenticated encryption with tags

## 🧪 Testing

### Automated Tests

```bash
# Run connectivity tests
python -m src.client test
```

**Expected output:**
```
Testing example.com... ✓ 93.184.216.34
Testing test.com... ✓ 192.168.1.100
Testing secure.example.com... ✓ 203.0.113.10
Testing nonexistent.com... ✗ Not found
```

### Manual Testing

**Test 1: Basic Query**
```bash
# Terminal 1
python -m src.server

# Terminal 2
python -m src.client query example.com
# Should show: IP Address: 93.184.216.34
```

**Test 2: Encrypted Query**
```bash
python -m src.client query example.com --encrypted
# Should show: Using encrypted query
# Should still resolve correctly
```

**Test 3: Non-existent Domain**
```bash
python -m src.client query nonexistent.example.com
# Should show: ✗ DOMAIN NOT FOUND
```

**Test 4: Signature Verification**
```python
python -c "
from src.crypto.signature import DNSRecordSigner
s = DNSRecordSigner()
r = {'domain': 'test.com', 'type': 'A', 'data': '1.2.3.4', 'ttl': 3600}
signed = s.sign_record(r)
print('✓ Valid:', s.verify_signature(signed))
"
```

**Test 5: Encryption**
```python
python -c "
from src.crypto.encryption import QueryEncryptor
e = QueryEncryptor()
enc = e.encrypt_query('example.com', 'A')
dec = e.decrypt_query(enc)
print('✓ Domain:', dec['domain'])
"
```

## 📊 Performance Metrics

| Operation | Time | Notes |
|-----------|------|-------|
| RSA Sign | ~2-3 ms | Per DNS record |
| RSA Verify | ~1-2 ms | Per signature check |
| AES Encrypt | ~0.5 ms | Per query |
| AES Decrypt | ~0.5 ms | Per response |
| **Total Overhead** | **~4-6 ms** | Per secure query |

**Throughput**: ~200-250 queries/second (single-threaded)

## 🐛 Troubleshooting

### Common Issues

**Issue 1: Module not found**
```bash
# ✗ Wrong way
python src/server.py

# ✓ Correct way
python -m src.server
```

**Issue 2: Address already in use**
```bash
# Use different port
python -m src.server --port 5454
```

**Issue 3: Permission denied on port 53**
```bash
# Use unprivileged port (>1024)
python -m src.server --port 5353
```

**Issue 4: Import errors**
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Verify virtual environment is active
which python  # Should show venv/bin/python
```

**Issue 5: Cryptography errors**
```bash
# Upgrade pip and reinstall
pip install --upgrade pip
pip install --force-reinstall cryptography pycryptodome
```

## 🎯 Use Cases

### 1. Enterprise Networks
- Internal DNS with cryptographic verification
- Prevent DNS poisoning attacks
- Audit trail of DNS queries

### 2. IoT Devices
- Secure device name resolution
- Authenticated endpoint discovery
- Prevent device spoofing

### 3. Privacy Applications
- Encrypted DNS queries
- Hide browsing patterns
- DNS-over-HTTPS alternative

### 4. Educational Purposes
- Learn DNS protocol internals
- Understand cryptographic concepts
- Practice secure system design

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/yourusername/secure-dns-simulator.git
cd secure-dns-simulator
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Coding Standards

- Follow PEP 8 style guide
- Add docstrings to all functions
- Include type hints where appropriate
- Write tests for new features

## 📄 License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025 SecureDNS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## 👥 Authors

- **Your Name** - *Initial work* - [YourGitHub](https://github.com/yourusername)

## 🙏 Acknowledgments

- RFC 4034 - DNSSEC Resource Records
- RFC 8484 - DNS-over-HTTPS
- Python Cryptography Community
- OpenSSL Project

## 📞 Support

- 📧 Email: your.email@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/secure-dns-simulator/issues)

## ⚠️ Disclaimer

This is an educational/demonstration project. For production DNS infrastructure, use established solutions like BIND9, PowerDNS, or Unbound with proper DNSSEC implementation.

