import hashlib
import secrets
import os

# --- UI HELPER FUNCTIONS ---
def print_header(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")

def print_step(text):
    print(f"\n>> {text}")

def print_info(label, value):
    print(f" [{label}]: {str(value)[:70]}...")

# --- Define Diffie-Hellman Constants G and P ---
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2

# --- PART A: STATEFUL PRNG ---
class SecurePRNG:
    def __init__(self, seed_int):
        # Initialize the state with the shared secret (hashed to 32 bytes)
        self.state = hashlib.sha256(str(seed_int).encode()).digest()

    def generate(self, n_bytes):
        # Generates n bytes while ensuring Rollback Resistance.
        output = b""
        while len(output) < n_bytes:
            # 1. Produce keystream block from current state
            block = hashlib.sha256(self.state).digest()
            output += block
            # 2. Update state immediately (One-way progression)
            # This prevents an attacker from reversing the state if they find it later.
            self.state = hashlib.sha256(block + self.state).digest()
        return output[:n_bytes]

def xor_crypt(data, prng):
    # Standard XOR stream cipher logic
    if isinstance(data, str):
        data = data.encode()
    keystream = prng.generate(len(data))
    return bytes([b ^ k for b, k in zip(data, keystream)])

# --- PART B: COMMUNICATION PROTOCOL ---
class Entity:
    def __init__(self, name):
        self.name = name
        # Generate a secure random private key
        self.private_key = secrets.randbelow(P)
        self.public_key = pow(G, self.private_key, P)
        self.session_prng = None

    def get_public_hex(self):
        return hex(self.public_key)

    def establish_session(self, partner_pub_hex):
        partner_pub = int(partner_pub_hex, 16)
        shared_secret = pow(partner_pub, self.private_key, P)
        self.session_prng = SecurePRNG(shared_secret)

class Network:
    def __init__(self):
        self.mallory = None 
    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload

# --- PART C: THE MALLORY MITM PROXY ---
class Mallory:
    def __init__(self):
        self.private_key = secrets.randbelow(P)
        self.public_key = pow(G, self.private_key, P)
        self.public_hex = hex(self.public_key)
        # Mallory maintains TWO sessions
        self.alice_prng = None
        self.bob_prng = None

    def intercept(self, sender, recipient, payload):
        # 1. Logic for Key Exchange Interception
        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)
            my_shared_secret = pow(remote_pub, self.private_key, P)
            
            if sender == "Alice":
                self.alice_prng = SecurePRNG(my_shared_secret)
            elif sender == "Bob":
                self.bob_prng = SecurePRNG(my_shared_secret)
            
            return self.public_hex 

        # 2. Logic for Message Interception/Modification
        if isinstance(payload, bytes):
            print(f"[MALLORY] Intercepting Encrypted Message from {sender}...")
            
            # Decrypt message from Alice
            plaintext = xor_crypt(payload, self.alice_prng).decode()
            print(f"[MALLORY] Decrypted Plaintext: '{plaintext}'")
            
            # Modify the message: Change '9pm' to '3am'
            modified_text = plaintext.replace("9pm", "3am")
            print(f"[MALLORY] Modified Message: '{modified_text}'")
            
            # Re-encrypt for Bob
            return xor_crypt(modified_text, self.bob_prng)
        
        return payload

# --- MAIN EXECUTION SIMULATION ---
def main():
    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")
    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    print_step("Step 1: Public Key Exchange")
    alice_pub = alice.get_public_hex()
    key_for_bob = net.send("Alice", "Bob", alice_pub)
    bob_pub = bob.get_public_hex()
    key_for_alice = net.send("Bob", "Alice", bob_pub)

    print_step("Step 2: Establishing Sessions")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    print(" [Status]: Shared Secret computed.")

    print_step("Step 3: Secure Message Transmission")
    # --- MODIFY THIS MESSAGE FOR YOUR ASSIGNMENT ---
    message = b"The secret meeting is at 9pm." 
    # -----------------------------------------------
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob decrypted", final_message.decode())

    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")
    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory

    print_step("Step 1: Mallory's Parameters")
    print_info("Mallory Private (m)", mallory.private_key)
    print_info("Mallory Public (M)", mallory.public_hex)

    print_step("Step 2: Compromised Key Exchange")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())

    print_step("Step 3: Poisoned Shared Secrets")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    print_step("Step 4: Interception")
    # Alice sends her message
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    
    # Bob decrypts what he received from the network
    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob received", final_message.decode())

    if b"3am" in final_message:
        print("\n[DANGER] MITM SUCCESS: Mallory modified the message in transit.")

if __name__ == "__main__":
    main()
