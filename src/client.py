#!/usr/bin/env python3
"""
SecureDNS Client - Simplified Version
Command-line client for querying SecureDNS server
"""

import socket
import json
import sys
from src.crypto.signature import DNSRecordSigner
from src.crypto.encryption import QueryEncryptor


class SecureDNSClient:
    """Simplified DNS client"""
    
    def __init__(self, server='localhost', port=5353):
        self.server = server
        self.port = port
        self.signer = DNSRecordSigner()
        self.encryptor = QueryEncryptor()
    
    def query(self, domain, record_type='A', encrypted=False, verify=True):
        """Query the DNS server"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Build query
            query = {
                'domain': domain,
                'type': record_type,
                'encrypted': encrypted
            }
            
            # Encrypt if requested
            if encrypted:
                query['data'] = self.encryptor.encrypt_query(domain, record_type)
            
            # Send query
            sock.sendto(json.dumps(query).encode(), (self.server, self.port))
            
            # Receive response
            data, _ = sock.recvfrom(4096)
            response = json.loads(data.decode())
            
            sock.close()
            
            # Verify signature if requested
            if verify and response.get('status') == 'success':
                signed_record = {
                    'record': {
                        'domain': response['domain'],
                        'type': response['type'],
                        'data': response['data'],
                        'ttl': response['ttl']
                    },
                    'signature': response['signature'],
                    'public_key': response['public_key']
                }
                response['verified'] = self.signer.verify_signature(signed_record)
            
            return response
            
        except socket.timeout:
            return {'status': 'error', 'message': 'Query timeout'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


def print_result(result):
    """Pretty print query result"""
    print("\n" + "="*60)
    
    if result['status'] == 'success':
        print("✓ QUERY SUCCESSFUL")
        print("="*60)
        print(f"Domain:       {result['domain']}")
        print(f"Type:         {result['type']}")
        print(f"IP Address:   {result['data']}")
        print(f"TTL:          {result['ttl']} seconds")
        print(f"Signed:       ✓ Yes")
        
        if 'verified' in result:
            status = "✓ Valid" if result['verified'] else "✗ Invalid"
            print(f"Verified:     {status}")
        
    elif result['status'] == 'not_found':
        print("✗ DOMAIN NOT FOUND")
        print("="*60)
        print(f"Domain:       {result['domain']}")
        print(f"Message:      {result.get('message', 'Not found')}")
        
    else:
        print("✗ QUERY FAILED")
        print("="*60)
        print(f"Error:        {result.get('message', 'Unknown error')}")
    
    print("="*60 + "\n")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='SecureDNS Client - Query cryptographically secured DNS records',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic query
  python client.py query example.com
  
  # Query specific record type
  python client.py query example.com --type A
  
  # Encrypted query
  python client.py query example.com --encrypted
  
  # Skip signature verification
  python client.py query example.com --no-verify
  
  # Test multiple domains
  python client.py test
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query a domain')
    query_parser.add_argument('domain', help='Domain name to query')
    query_parser.add_argument('--type', default='A', help='Record type (default: A)')
    query_parser.add_argument('--server', default='localhost', help='DNS server address')
    query_parser.add_argument('--port', type=int, default=5353, help='DNS server port')
    query_parser.add_argument('--encrypted', action='store_true', help='Use encrypted query')
    query_parser.add_argument('--no-verify', action='store_true', help='Skip signature verification')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run connectivity tests')
    test_parser.add_argument('--server', default='localhost', help='DNS server address')
    test_parser.add_argument('--port', type=int, default=5353, help='DNS server port')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    if args.command == 'query':
        client = SecureDNSClient(args.server, args.port)
        
        print(f"\n🔍 Querying {args.domain} ({args.type})...")
        if args.encrypted:
            print("🔒 Using encrypted query")
        
        result = client.query(
            args.domain,
            args.type,
            encrypted=args.encrypted,
            verify=not args.no_verify
        )
        
        print_result(result)
    
    elif args.command == 'test':
        client = SecureDNSClient(args.server, args.port)
        
        print("\n" + "="*60)
        print("Running Connectivity Tests")
        print("="*60 + "\n")
        
        test_domains = [
            ('example.com', 'A'),
            ('test.com', 'A'),
            ('secure.example.com', 'A'),
            ('nonexistent.com', 'A')
        ]
        
        for domain, record_type in test_domains:
            print(f"Testing {domain}...", end=' ')
            result = client.query(domain, record_type)
            
            if result['status'] == 'success':
                print(f"✓ {result['data']}")
            elif result['status'] == 'not_found':
                print("✗ Not found")
            else:
                print(f"✗ Error: {result.get('message', 'Unknown')}")
        
        print("\n" + "="*60 + "\n")


if __name__ == '__main__':
    main()
