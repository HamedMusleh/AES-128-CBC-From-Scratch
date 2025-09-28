# task2_aes_avalanche_analysis.py
# Avalanche experiments + basic error propagation demos for CBC.
from PIL import Image
import numpy as np
import os
import random
from task2_aes import cbc_encrypt, cbc_decrypt, xor_bytes, key_expansion_128, pad_pkcs7

# Helper functions
def flip_one_bit(b: bytes) -> bytes:
    idx = random.randrange(len(b))
    bit = 1 << random.randrange(8)
    ba = bytearray(b)
    ba[idx] ^= bit
    return bytes(ba), idx*8 + (bit.bit_length() - 1)

def hamming_bytes(a: bytes, b: bytes) -> int:
    """Return number of differing bits between two byte strings."""
    assert len(a) == len(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def blocks(data: bytes, block_size=16):
    """Yield successive blocks of data."""
    for i in range(0, len(data), block_size):
        yield data[i:i+block_size]

def pretty_line(cols):
    return " | ".join(f"{c:>8}" for c in cols)

# ---------- Avalanche Effect Experiments ----------
def experiment_avalanche(trials=10):
    print("\n[Experiment A] Flip one bit in plaintext (single 16-byte block)")
    for t in range(1, trials+1):
        P = os.urandom(16)
        K = os.urandom(16)
        IV = os.urandom(16)
        round_keys = key_expansion_128(K)

        C1 = cbc_encrypt(P, round_keys, IV)
        P2, bit_index = flip_one_bit(P)
        C2 = cbc_encrypt(P2, round_keys, IV)

        # طباعة مفصلة
        print(f"\nTrial {t}:")
        print(f"PLAIN (P1) : {P.hex().upper()}")
        print(f"IV         : {IV.hex().upper()}")
        print(f"KEY        : {K.hex().upper()}")
        print(f"C1         : {C1.hex().upper()}")
        print(f"PLAIN (P2) : {P2.hex().upper()}")
        print(f"C2         : {C2.hex().upper()}")
        print(f"Flipped Bit: {bit_index}")
        print(f"Hamming(C1,C2): {hamming_bytes(C1, C2)}")

    print("\n[Experiment B] Flip one bit in key")
    for t in range(1, trials+1):
        P = os.urandom(16)
        K = os.urandom(16)
        IV = os.urandom(16)
        round_keys = key_expansion_128(K)

        K2, bit_index = flip_one_bit(K)
        round_keys2 = key_expansion_128(K2)
        C1 = cbc_encrypt(P, round_keys, IV)
        C2 = cbc_encrypt(P, round_keys2, IV)

        print(f"\nTrial {t}:")
        print(f"PLAIN (P1) : {P.hex().upper()}")
        print(f"IV         : {IV.hex().upper()}")
        print(f"KEY        : {K.hex().upper()}")
        print(f"Flipped KEY: {K2.hex().upper()}")
        print(f"C1         : {C1.hex().upper()}")
        print(f"C2         : {C2.hex().upper()}")
        print(f"Flipped Bit: {bit_index}")
        print(f"Hamming(C1,C2): {hamming_bytes(C1, C2)}")



# ---------- Extended CBC Error Experiments ----------
def experiment_bit_error_in_ciphertext(num_blocks=4):
    print("\n[Extended A] Single bit error in ciphertext")
    P = os.urandom(16 * num_blocks)
    K = os.urandom(16)
    IV = os.urandom(16)
    round_keys = key_expansion_128(K)
    C = cbc_encrypt(P, round_keys, IV)

    # Original plaintext blocks
    P_blocks = [P[j:j+16] for j in range(0, len(P), 16)]
    print("\nOriginal Plaintext Blocks:")
    for i, blk in enumerate(P_blocks):
        print(f"P{i} : {blk.hex().upper()}")

    print(f"IV : {IV.hex().upper()}")
    print(f"KEY: {K.hex().upper()}")

    # flip one bit in ciphertext
    C_err, bit_index = flip_one_bit(C)
    
    # divide ciphertext into blocks for display
    C_blocks = [C[j:j+16] for j in range(0, len(C), 16)]
    C_err_blocks = [C_err[j:j+16] for j in range(0, len(C_err), 16)]
    print("\nCiphertext Blocks (Original vs Error):")
    for i, (c_orig, c_err) in enumerate(zip(C_blocks, C_err_blocks)):
        print(f"C{i} original: {c_orig.hex().upper()}")
        print(f"C{i} error   : {c_err.hex().upper()}")

    # Decrypt the errored ciphertext
    P_dec = cbc_decrypt(C_err, round_keys, IV)
    P_dec_blocks = [P_dec[j:j+16] for j in range(0, len(P_dec), 16)]

    # Print plaintext after error with CHANGED/OK
    print("\nPlaintext after error in ciphertext:")
    for i, (orig, dec) in enumerate(zip(P_blocks, P_dec_blocks)):
        status = "CHANGED" if orig != dec else "OK"
        print(f"P{i}_dec : {dec.hex().upper()} ({status})")

    print(f"\nFlipped bit at global bit index {bit_index}.")
    print("Observation: exactly two consecutive plaintext blocks should be corrupted.")



def experiment_loss_of_block(num_blocks=6):
    print("\n[Extended B] Loss of a ciphertext block")
    P = os.urandom(16 * num_blocks)
    K = os.urandom(16)
    IV = os.urandom(16)
    round_keys = key_expansion_128(K)
    C = cbc_encrypt(P, round_keys, IV)

    # print original plaintext blocks
    print("\nOriginal Plaintext Blocks:")
    for i, blk in enumerate([P[j:j+16] for j in range(0, len(P), 16)]):
        print(f"P{i} : {blk.hex().upper()}")
    print(f"IV : {IV.hex().upper()}")
    print(f"KEY: {K.hex().upper()}")

    # drop a random middle block
    j = random.randrange(1, num_blocks-1)
    C_blocks = [C[i:i+16] for i in range(0, len(C), 16)]
    dropped_block = C_blocks.pop(j)
    C_lost = b"".join(C_blocks)

    # decrypt after block loss
    P_dec = cbc_decrypt(C_lost, round_keys, IV)

    # print decrypted blocks with status
    print(f"\nDropped ciphertext block index j={j}.")
    print("Decoded Plaintext Blocks after block loss:")
    P_blocks_dec = [P_dec[i:i+16] for i in range(0, len(P_dec), 16)]
    P_blocks_orig = [P[i:i+16] for i in range(0, len(P), 16)]
    for i, (orig, dec) in enumerate(zip(P_blocks_orig, P_blocks_dec)):
        status = "CHANGED" if orig != dec else "OK"
        print(f"P{i}_dec : {dec.hex().upper()} ({status})")

    print("Observation: block j and j+1 become wrong; decryption resynchronizes after that.")
    
#---------------------------------------------------------------------------

img = Image.open("image_1.png").convert("L")
data = np.array(img)
flat_data = data.flatten().tobytes()

key = os.urandom(16)
IV = os.urandom(16)
round_keys = key_expansion_128(key)

# --- Padding ---
padded_data = pad_pkcs7(flat_data)

ciphertext = cbc_encrypt(padded_data, round_keys, IV)

cipher_bytes = np.frombuffer(ciphertext, dtype=np.uint8)
side_len = int(np.sqrt(len(cipher_bytes)))
cipher_bytes = cipher_bytes[:side_len*side_len]
cipher_image = cipher_bytes.reshape((side_len, side_len))

img_cipher = Image.fromarray(cipher_image, mode='L')
img_cipher.show()

#-----------------------------------------------------------------------------

# ---------- Main ----------
if __name__ == "__main__":
    random.seed(1337)
    experiment_avalanche(trials=10)
    experiment_bit_error_in_ciphertext(num_blocks=5)
    experiment_loss_of_block(num_blocks=6)
