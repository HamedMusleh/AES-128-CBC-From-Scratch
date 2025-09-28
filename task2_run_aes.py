from binascii import unhexlify
from task2_aes import key_expansion_128, cbc_encrypt, cbc_decrypt

def main():
    op = input("Select operation — Encrypt (E) or Decrypt (D): ").strip().upper()
    data_hex = input("Enter plaintext/ciphertext (hex, any length): ").strip().replace(" ", "")
    key_hex = input("Enter 128-bit AES key (hex, 32 hex chars): ").strip().replace(" ", "")
    iv_hex  = input("Enter 128-bit IV (hex, 32 hex chars): ").strip().replace(" ", "")

    try:
        data = unhexlify(data_hex)
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
    except Exception as e:
        print("Error: invalid hex input.", e)
        return

    if len(key) != 16 or len(iv) != 16:
        print("Error: key and IV must be exactly 16 bytes (32 hex chars).")
        return

    round_keys = key_expansion_128(key)

    if op == "E":
        ciphertext = cbc_encrypt(data, round_keys, iv)
        print("Ciphertext (hex):", ciphertext.hex())
    elif op == "D":
        try:
            plaintext = cbc_decrypt(data, round_keys, iv)
            print("Decrypted plaintext (hex):", plaintext.hex())
            print("Decrypted plaintext (ASCII):", plaintext.decode(errors="ignore"))
        except Exception as e:
            print("Decryption failed:", e)
    else:
        print("Invalid operation. Use 'E' or 'D'.")

if __name__ == "__main__":
    main()
