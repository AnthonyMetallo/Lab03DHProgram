import hashlib
import os

# --- Class Implementations ---

class SecurePRNG:
    """Stateful PRNG with Rollback Resistance."""
    def __init__(self, shared_secret):
        # Initialize state with shared secret (hashed to 32 bytes)
        self.state = hashlib.sha256(str(shared_secret).encode()).digest()

    def generate(self, n):
        """Produces n pseudorandom bytes and updates state."""
        keystream = b""
        for _ in range(n // 32 + 1):
            # Generate bytes from current state
            keystream += hashlib.sha256(self.state).digest()
            # Update state for Rollback Resistance: State = H(State + Keystream)
            self.state = hashlib.sha256(self.state + keystream).digest()
        return keystream[:n]

def stream_cipher(plaintext, prng):
    """XOR Cipher using PRNG keystream."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    keystream = prng.generate(len(plaintext))
    
    # XOR operation
    ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
    return ciphertext

class Entity:
    """Alice or Bob."""
    def __init__(self, name, p, g):
        self.name = name
        self.p = p
        self.g = g
        self.private_key = int.from_bytes(os.urandom(16), 'big') % p
        self.public_key = pow(g, self.private_key, p)
        self.shared_secret = None
        self.prng = None

    def get_public_hex(self):
        return hex(self.public_key)

    def establish_session(self, other_public_hex):
        other_public = int(other_public_hex, 16)
        self.shared_secret = pow(other_public, self.private_key, self.p)
        self.prng = SecurePRNG(self.shared_secret)
        return self.shared_secret

class Mallory:
    """Interceptor (MITM)."""
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = int.from_bytes(os.urandom(16), 'big') % p
        self.public_key = pow(g, self.private_key, p)
        self.secrets = {} # Stores secrets with Alice and Bob

    def get_public_hex(self):
        return hex(self.public_key)

    def intercept_key(self, sender_name, public_hex):
        """Intercepts key, establishes fake secret with sender."""
        public_key = int(public_hex, 16)
        # S = OtherPubKey^MalloryPrivKey % p
        self.secrets[sender_name] = pow(public_key, self.private_key, self.p)
        return hex(self.public_key)

    def intercept_message(self, encrypted_msg, sender_name, recipient_name):
        """Decrypts, modifies, and re-encrypts."""
        # 1. Decrypt using sender's secret
        prng_sender = SecurePRNG(self.secrets[sender_name])
        decrypted = stream_cipher(encrypted_msg, prng_sender).decode()
        
        print(f"[ATTACK] Mallory intercepted: {decrypted}")
        
        # 2. Modify message
        modified = decrypted.replace("10am", "12pm")
        print(f"[ATTACK] Mallory modified to: {modified}")
        
        # 3. Re-encrypt using recipient's secret
        prng_recipient = SecurePRNG(self.secrets[recipient_name])
        return stream_cipher(modified, prng_recipient)

# --- Main Simulation ---

def main():
    # Parameters derived from context
    p = 23
    g = 5
    
    alice = Entity("Alice", p, g)
    bob = Entity("Bob", p, g)
    mallory = Mallory(p, g)

    print("--- Scenario A: Benign Communication ---")
    
    # Exchange Keys
    a_pub = alice.get_public_hex()
    b_pub = bob.get_public_hex()
    
    alice.establish_session(b_pub)
    bob.establish_session(a_pub)
    
    # Alice sends message
    message = "We are meeting at 10am tomorrow."
    encrypted = stream_cipher(message, alice.prng)
    
    # Bob decrypts
    decrypted = stream_cipher(encrypted, bob.prng).decode()
    
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    if message == decrypted:
        print("[SUCCESS] Secrets Match!")

    print("\n--- Scenario B: MITM Attack ---")
    
    # Mallory Intercepts Keys
    m_pub_for_alice = mallory.intercept_key("Alice", a_pub)
    m_pub_for_bob = mallory.intercept_key("Bob", b_pub)
    
    # Alice and Bob establish sessions with Mallory
    alice.establish_session(m_pub_for_alice)
    bob.establish_session(m_pub_for_bob)
    
    # Alice sends message
    encrypted_for_bob = stream_cipher(message, alice.prng)
    
    # Mallory Intercepts Message
    tampered_msg = mallory.intercept_message(encrypted_for_bob, "Alice", "Bob")
    
    # Bob decrypts tampered message
    decrypted_by_bob = stream_cipher(tampered_msg, bob.prng).decode()
    
    print(f"Bob received: {decrypted_by_bob}")
    if decrypted_by_bob != message:
        print("[ATTACK] ATTACK SUCCESS: Bob received modified message.")

if __name__ == "__main__":
    main()
