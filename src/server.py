#!/usr/bin/env python3
"""
SecureDNS Server - Simplified Version
A lightweight DNS server with cryptographic security features
"""

import socket
import json
import threading
from datetime import datetime
from src.crypto.signature import DNSRecordSigner
from src.crypto.encryption import QueryEncryptor


class SecureDNSServer:
    """Simplified secure DNS server"""
    
    def __init__(self, host='0.0.0.0', port=5353):
        self.host = host
        self.port = port
        self.running = False
        
        # Initialize crypto components
        self.signer = DNSRecordSigner()
        self.encryptor = QueryEncryptor()
        
        # Simple in-memory DNS records storage
        self.records = {}
        
        # Statistics
        self.query_count = 0
        
        # Load initial records
        self._load_sample_records()
    
    def _load_sample_records(self):
        """Load sample DNS records"""
        sample_data = [
            {'domain': 'example.com', 'type': 'A', 'data': '93.184.216.34', 'ttl': 3600},
            {'domain': 'test.com', 'type': 'A', 'data': '192.168.1.100', 'ttl': 3600},
            {'domain': 'secure.example.com', 'type': 'A', 'data': '203.0.113.10', 'ttl': 7200},
            {'domain': 'api.test.com', 'type': 'A', 'data': '198.51.100.42', 'ttl': 1800},
        ]
        
        for record in sample_data:
            # Sign each record
            signed = self.signer.sign_record(record)
            key = f"{record['domain']}:{record['type']}"
            self.records[key] = signed
        
        print(f"✓ Loaded {len(sample_data)} DNS records")
    
    def start(self):
        """Start the server"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.host, self.port))
            self.running = True
            
            print(f"\n{'='*60}")
            print(f"  SecureDNS Server Started")
            print(f"{'='*60}")
            print(f"  Address: {self.host}:{self.port}")
            print(f"  Features: RSA Signatures + AES Encryption")
            print(f"  Press Ctrl+C to stop")
            print(f"{'='*60}\n")
            
            while self.running:
                try:
                    # Receive query
                    data, addr = sock.recvfrom(4096)
                    
                    # Handle in new thread
                    thread = threading.Thread(
                        target=self._handle_query,
                        args=(data, addr, sock),
                        daemon=True
                    )
                    thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")
        
        finally:
            self.running = False
            sock.close()
            print(f"\n✓ Server stopped. Total queries: {self.query_count}")
    
    def _handle_query(self, data, addr, sock):
        """Handle DNS query"""
        try:
            # Parse query
            query = json.loads(data.decode())
            self.query_count += 1
            
            domain = query['domain']
            record_type = query.get('type', 'A')
            encrypted = query.get('encrypted', False)
            
            print(f"[{self.query_count}] Query: {domain} ({record_type}) from {addr[0]}")
            
            # Handle encrypted query
            if encrypted:
                decrypted = self.encryptor.decrypt_query(query['data'])
                if decrypted:
                    domain = decrypted['domain']
                    record_type = decrypted['type']
                    print(f"    → Decrypted: {domain}")
            
            # Lookup record
            key = f"{domain}:{record_type}"
            if key in self.records:
                signed_record = self.records[key]
                response = {
                    'status': 'success',
                    'domain': domain,
                    'type': record_type,
                    'data': signed_record['record']['data'],
                    'ttl': signed_record['record']['ttl'],
                    'signature': signed_record['signature'],
                    'public_key': signed_record['public_key'],
                    'timestamp': datetime.now().isoformat()
                }
                print(f"    ✓ Resolved: {response['data']}")
            else:
                response = {
                    'status': 'not_found',
                    'domain': domain,
                    'message': 'Domain not found'
                }
                print(f"    ✗ Not found")
            
            # Send response
            sock.sendto(json.dumps(response).encode(), addr)
            
        except Exception as e:
            print(f"    Error handling query: {e}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureDNS Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host address')
    parser.add_argument('--port', type=int, default=5353, help='Port number')
    args = parser.parse_args()
    
    server = SecureDNSServer(args.host, args.port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nShutting down...")


if __name__ == '__main__':
    main()
