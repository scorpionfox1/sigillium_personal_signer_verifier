# simple script to generate an Ed25519 keypair from a 24-word mnemonic
# for testing purposes only. Do not use in production.

from mnemonic import Mnemonic
from nacl.signing import SigningKey
import hashlib

mnemo = Mnemonic("english")

# 24-word mnemonic → 256 bits of entropy
words = mnemo.generate(strength=256)
seed = mnemo.to_seed(words)  # 64 bytes

# Derive Ed25519 key from seed
sk = SigningKey(seed[:32])
pk = sk.verify_key

print("mnemonic:", words)
print("private_key_hex:", sk.encode().hex())
print("public_key_hex:", pk.encode().hex())
