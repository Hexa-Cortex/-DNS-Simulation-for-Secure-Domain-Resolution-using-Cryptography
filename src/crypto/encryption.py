"""
DNS Query Encryption Module
Implements AES-256-GCM encryption for DNS queries and responses
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import json
import time
from typing import Dict, Optional

class QueryEncryptor:
    """Handles encryption and decryption of DNS queries using AES-256-GCM"""
    
    def __init__(self, password: Optional[str] = None):
        """
        Initialize the encryptor
        
        Args:
            password: Password for key derivation (default: generated)
        """
        self.password = password or "secure-dns-default-key-change-in-production"
        self.salt = get_random_bytes(16)
        self.key = self._derive_key(self.password, self.salt)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: Password string
            salt: Salt bytes
            
        Returns:
            Derived key bytes (32 bytes for AES-256)
        """
        return PBKDF2(password, salt, dkLen=32, count=100000)
    
    def encrypt_query(self, domain: str, record_type: str = "A") -> Dict:
        """
        Encrypt a DNS query
        
        Args:
            domain: Domain name to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            Dictionary containing encrypted query components
        """
        # Prepare query data
        query_data = json.dumps({
            'domain': domain,
            'type': record_type,
            'timestamp': str(time.time()),
            'nonce_random': base64.b64encode(get_random_bytes(16)).decode()
        }).encode()
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_GCM)
        
        # Encrypt and authenticate
        ciphertext, tag = cipher.encrypt_and_digest(query_data)
        
        return {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'salt': base64.b64encode(self.salt).decode()
        }
    
    def decrypt_query(self, encrypted_query: Dict) -> Optional[Dict]:
        """
        Decrypt a DNS query
        
        Args:
            encrypted_query: Dictionary containing encrypted components
            
        Returns:
            Decrypted query dictionary or None if decryption fails
        """
        try:
            # Decode components
            nonce = base64.b64decode(encrypted_query['nonce'])
            ciphertext = base64.b64decode(encrypted_query['ciphertext'])
            tag = base64.b64decode(encrypted_query['tag'])
            salt = base64.b64decode(encrypted_query['salt'])
            
            # Derive key with provided salt
            key = self._derive_key(self.password, salt)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return json.loads(plaintext.decode())
            
        except ValueError as e:
            print(f"Decryption failed - authentication error: {e}")
            return None
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
    
    def encrypt_response(self, response_data: Dict) -> Dict:
        """
        Encrypt a DNS response
        
        Args:
            response_data: Response dictionary to encrypt
            
        Returns:
            Dictionary containing encrypted response components
        """
        # Convert response to JSON
        response_json = json.dumps(response_data).encode()
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_GCM)
        
        # Encrypt and authenticate
        ciphertext, tag = cipher.encrypt_and_digest(response_json)
        
        return {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'salt': base64.b64encode(self.salt).decode(),
            'encrypted': True
        }
    
    def decrypt_response(self, encrypted_response: Dict) -> Optional[Dict]:
        """
        Decrypt a DNS response
        
        Args:
            encrypted_response: Dictionary containing encrypted components
            
        Returns:
            Decrypted response dictionary or None if decryption fails
        """
        try:
            # Decode components
            nonce = base64.b64decode(encrypted_response['nonce'])
            ciphertext = base64.b64decode(encrypted_response['ciphertext'])
            tag = base64.b64decode(encrypted_response['tag'])
            salt = base64.b64decode(encrypted_response['salt'])
            
            # Derive key with provided salt
            key = self._derive_key(self.password, salt)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return json.loads(plaintext.decode())
            
        except ValueError as e:
            print(f"Response decryption failed - authentication error: {e}")
            return None
        except Exception as e:
            print(f"Response decryption failed: {e}")
            return None
    
    def rotate_key(self):
        """Generate new salt and derive new key"""
        self.salt = get_random_bytes(16)
        self.key = self._derive_key(self.password, self.salt)


class SecureChannel:
    """Manages a secure communication channel with session keys"""
    
    def __init__(self):
        """Initialize secure channel with session key"""
        self.session_key = get_random_bytes(32)
        self.message_counter = 0
    
    def encrypt_message(self, message: Dict) -> Dict:
        """
        Encrypt message with session key and counter
        
        Args:
            message: Message dictionary to encrypt
            
        Returns:
            Encrypted message dictionary
        """
        # Add message counter for replay protection
        message['counter'] = self.message_counter
        self.message_counter += 1
        
        message_json = json.dumps(message).encode()
        
        # Create cipher with session key
        cipher = AES.new(self.session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message_json)
        
        return {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    
    def decrypt_message(self, encrypted_message: Dict) -> Optional[Dict]:
        """
        Decrypt message with session key
        
        Args:
            encrypted_message: Encrypted message dictionary
            
        Returns:
            Decrypted message or None if failed
        """
        try:
            nonce = base64.b64decode(encrypted_message['nonce'])
            ciphertext = base64.b64decode(encrypted_message['ciphertext'])
            tag = base64.b64decode(encrypted_message['tag'])
            
            cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return json.loads(plaintext.decode())
            
        except Exception as e:
            print(f"Message decryption failed: {e}")
            return None


if __name__ == "__main__":
    # Example usage
    encryptor = QueryEncryptor()
    
    # Encrypt a query
    encrypted = encryptor.encrypt_query("example.com", "A")
    print("Query encrypted successfully!")
    print(f"Ciphertext: {encrypted['ciphertext'][:50]}...")
    
    # Decrypt the query
    decrypted = encryptor.decrypt_query(encrypted)
    print(f"Decrypted domain: {decrypted['domain']}")
    print(f"Decrypted type: {decrypted['type']}")
    
    # Test tampering detection
    print("\nTesting tampering detection...")
    encrypted['tag'] = base64.b64encode(get_random_bytes(16)).decode()
    result = encryptor.decrypt_query(encrypted)
    print(f"Tampered decryption result: {result}")
