from binascii import unhexlify, hexlify
rcon_table = [
    0x00,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,0x1B, 0x36]

# ---------------- GF(2^8) inversion (Extended Euclid) ----------------
def gf256_inv(a: int) -> int:
    if a == 0:
        return 0
    modulus = 0x11B
    r0, r1 = modulus, a
    t0, t1 = 0, 1
    while r1 != 0:
        deg_r0 = r0.bit_length() - 1
        deg_r1 = r1.bit_length() - 1
        shift = deg_r0 - deg_r1
        if shift < 0:
            r0, r1 = r1, r0
            t0, t1 = t1, t0
            shift = -shift
        r0 ^= r1 << shift
        t0 ^= t1 << shift
    # reduce t0 modulo modulus so it's < 256
    while t0.bit_length() > 8:
        shift = t0.bit_length() - 9
        t0 ^= modulus << shift
    return t0 & 0xFF

# ---------------- AES affine mapping ----------------
def aes_affine_map(byte_in: int) -> int:
    c = 0x63
    out_byte = 0
    for i in range(8):
        bit = ((byte_in >> i) & 1) \
              ^ ((byte_in >> ((i + 4) % 8)) & 1) \
              ^ ((byte_in >> ((i + 5) % 8)) & 1) \
              ^ ((byte_in >> ((i + 6) % 8)) & 1) \
              ^ ((byte_in >> ((i + 7) % 8)) & 1) \
              ^ ((c >> i) & 1)
        out_byte |= (bit << i)
    return out_byte

# ---------------- AES INV-affine mapping ----------------
def aes_INV_affine_map(byte_in: int) -> int:

    c = 0x05
    out_byte = 0
    for i in range(8):
        bit = ((byte_in >> ((i + 2) % 8)) & 1) \
              ^ ((byte_in >> ((i + 5) % 8)) & 1) \
              ^ ((byte_in >> ((i + 7) % 8)) & 1) \
              ^ ((c >> i) & 1)
        out_byte |= (bit << i)
    return out_byte


# ---------------- state helpers ----------------
def hex_string_to_state16(hex_str: str):
    """Convert 32-hex (16 bytes) to AES state 4x4 (column-major)."""
    s = hex_str.replace(" ", "")
    if len(s) != 32:
        raise ValueError("Expected exactly 32 hex chars (16 bytes) for state conversion.")
    bytes_data = [int(s[i:i+2], 16) for i in range(0, 32, 2)]
    state = [[0]*4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = bytes_data[col*4 + row]
    return state

def state16_to_hex_string(state):
    """Convert 4x4 state back to 32-hex string (column-major)."""
    out = ""
    for col in range(4):
        for row in range(4):
            out += f"{state[row][col]:02x}"
    return out

def sub_bytes_state(state):
    """Apply gf256_inv then affine map to every byte in 4x4 state."""
    new = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            v = state[r][c]
            inv = gf256_inv(v)
            new[r][c] = aes_affine_map(inv)
    return new

#--------------------------------------------------

def inv_sub_bytes_state(state):
    """Apply InvSubBytes: inverse affine map ثم inverse GF(2^8) inverse to every byte in 4x4 state."""
    new = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            v = state[r][c]
            mapped = aes_INV_affine_map(v)
            inv = gf256_inv(mapped)
            new[r][c] = inv
    return new

def pretty_print_state(state, title=None):
    if title:
        print(title)
    for r in range(4):
        print(" ".join(f"{state[r][c]:02x}" for c in range(4)))
    print()
#------------------------ Shift Row ------------------------------------
def shift_rows(state):
    """Perform AES ShiftRows on 4x4 state matrix (list of lists).
    Row 0: no shift
    Row 1: shift left by 1
    Row 2: shift left by 2
    Row 3: shift left by 3
    """
    new_state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_state[r][c] = state[r][(c + r) % 4]
    return new_state
#-------------------------------------------------------------

#------------------------ INV_ Shift Row ------------------------------------
def inv_shift_rows(state):
    """Perform AES InvShiftRows on 4x4 state matrix (list of lists).
    Row 0: no shift
    Row 1: shift right by 1
    Row 2: shift right by 2
    Row 3: shift right by 3
    """
    new_state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_state[r][c] = state[r][(c - r) % 4]
    return new_state

#-------------------------------------------------------------


#------------------ mix column --------------------
def xtime(a):
    """Multiply by 2 in GF(2^8)"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gf256_mul(a, b):
    """Multiply two bytes in GF(2^8) without lookup tables"""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return res


def mix_single_column(col):
    """Apply MixColumns to a single 4-byte column"""
    a0, a1, a2, a3 = col
    return [
        gf256_mul(a0, 2) ^ gf256_mul(a1, 3) ^ a2 ^ a3,
        a0 ^ gf256_mul(a1, 2) ^ gf256_mul(a2, 3) ^ a3,
        a0 ^ a1 ^ gf256_mul(a2, 2) ^ gf256_mul(a3, 3),
        gf256_mul(a0, 3) ^ a1 ^ a2 ^ gf256_mul(a3, 2)
    ]

def mix_columns(state):
    """Apply MixColumns to the full 4x4 state"""
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed_col = mix_single_column(col)
        for r in range(4):
            new_state[r][c] = mixed_col[r]
    return new_state

#--------------------------------------------------------

def inv_mix_single_column(col):
    """Apply InvMixColumns to a single 4-byte column"""
    a0, a1, a2, a3 = col
    return [
        gf256_mul(a0, 0x0e) ^ gf256_mul(a1, 0x0b) ^ gf256_mul(a2, 0x0d) ^ gf256_mul(a3, 0x09),
        gf256_mul(a0, 0x09) ^ gf256_mul(a1, 0x0e) ^ gf256_mul(a2, 0x0b) ^ gf256_mul(a3, 0x0d),
        gf256_mul(a0, 0x0d) ^ gf256_mul(a1, 0x09) ^ gf256_mul(a2, 0x0e) ^ gf256_mul(a3, 0x0b),
        gf256_mul(a0, 0x0b) ^ gf256_mul(a1, 0x0d) ^ gf256_mul(a2, 0x09) ^ gf256_mul(a3, 0x0e),
    ]

def inv_mix_columns(state):
    """Apply InvMixColumns to the full 4x4 state"""
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed_col = inv_mix_single_column(col)
        for r in range(4):
            new_state[r][c] = mixed_col[r]
    return new_state




#----------------------------- G function ------------------------------
def sub_word(word):
    return [aes_affine_map(gf256_inv(b)) for b in word]

def rot_word(word):
    return [word[1], word[2], word[3], word[0]]

def g_function(word, round_i):
    t = rot_word(word)
    t = sub_word(t)
    t[0] ^= rcon_table[round_i]
    return t
#--------------------------------------------------------

#----------------------------- Key function ------------------------------

def key_expansion_128(key16bytes: bytes):
    assert len(key16bytes) == 16
    words = [list(key16bytes[i:i+4]) for i in range(0, 16, 4)]  # w0..w3
    for i in range(4, 44):
        temp = words[i-1].copy()
        if i % 4 == 0:
            temp = g_function(temp, i//4)
        neww = [a ^ b for a, b in zip(words[i-4], temp)]
        words.append(neww)
    round_keys = []
    for r in range(0, 44, 4):
        rk_bytes = bytes([b for w in words[r:r+4] for b in w])
        round_keys.append(rk_bytes)  # K0..K10
    return round_keys

#--------------------------------------------------------

#----------------------------- Add Key function ------------------------------

def add_round_key(state, round_key_bytes):
    """XOR state مع round key (16 bytes)"""
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            new_state[r][c] = state[r][c] ^ round_key_bytes[c*4 + r]
    return new_state


#------------------------------------------------------------


def pad_pkcs7(data: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]



#----------------------CBC MODE ------------------------------------------#


def aes_encrypt_block(block_bytes: bytes, round_keys):
    state = hex_string_to_state16(block_bytes.hex())
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = sub_bytes_state(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes_state(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return bytes.fromhex(state16_to_hex_string(state))


def aes_decrypt_block(block_bytes: bytes, round_keys):
    state = hex_string_to_state16(block_bytes.hex())
    state = add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes_state(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes_state(state)
    state = add_round_key(state, round_keys[0])
    return bytes.fromhex(state16_to_hex_string(state))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]*pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def cbc_encrypt(plaintext: bytes, round_keys, iv: bytes) -> bytes:
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        print(block.hex())
        xored = xor_bytes(block, prev_block)
        encrypted = aes_encrypt_block(xored, round_keys)
        print(encrypted.hex())
        ciphertext += encrypted
        prev_block = encrypted
    return ciphertext

def cbc_decrypt(ciphertext: bytes, round_keys, iv: bytes) -> bytes:
    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes_decrypt_block(block, round_keys)
        xored = xor_bytes(decrypted, prev_block)
        plaintext += xored
        prev_block = block
    return plaintext
