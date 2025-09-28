# 🔐 AES-128 in CBC Mode – From Scratch

## 📖 Overview
This project implements **AES-128 encryption** in **Cipher Block Chaining (CBC) mode** entirely from first principles.  
All operations are coded directly over **GF(2^8)** without using pre-computed lookup tables, making the math behind AES explicit.  
The system includes full AES stages, padding, chaining logic, and experimental analysis of diffusion and error propagation.

---

## ⚙️ Implementation Details

### 🔑 AES Core Stages
- **SubBytes**: Byte substitution using multiplicative inverses in GF(2^8) + affine transform.  
- **ShiftRows**: Cyclic row shifts to achieve inter-column diffusion.  
- **MixColumns**: Column mixing via GF(2^8) matrix multiplication.  
- **AddRoundKey**: XOR state with round key.  
- **Key Expansion**: Round keys derived with RotWord, SubWord, and round constants.  

### 📦 CBC Mode
- **Encryption**  
  - `C1 = AES(P1 ⊕ IV)`  
  - `Ci = AES(Pi ⊕ Ci-1)`  
- **Decryption**  
  - `P1 = AES⁻¹(C1) ⊕ IV`  
  - `Pi = AES⁻¹(Ci) ⊕ Ci-1`  
- **Padding**: PKCS#7 ensures plaintext fits into 128-bit blocks.  
- **Security**: Unlike ECB, CBC hides repeating patterns, preventing data leakage.  

### 🧮 Mathematical Choices
- **No lookup tables**: All transformations computed algorithmically.  
- **GF(2^8)** operations: Multiplication, inversion, affine transforms implemented directly.  
- **RC[i]** constants only (per AES standard).  

---

## ✅ Verification
- **Correctness tested** against:
  - FIPS-197 AES test vectors.  
  - NIST SP 800-38A CBC test vectors.  
- **Encryption & Decryption** matched expected outputs for all cases.  

---

## 🧪 Experimental Analysis

### 🔄 Avalanche Effect
- Flipping **1 plaintext bit → ~64/128 ciphertext bits flipped**.  
- Flipping **1 key bit → ~63.8/128 ciphertext bits flipped**.  
- Confirms strong diffusion and avalanche property.  

### ⚡ Error Propagation
- **Bit flip in ciphertext**: corrupts 1 full block + 1 bit in the next block.  
- **Lost block**: desynchronizes 2 blocks, then recovery resumes.  
- Matches CBC’s theoretical error behavior.  

### 🖼️ Visual Tests
- Encrypting a checkerboard image with **ECB** leaked visible patterns.  
- Encrypting the same image with **CBC** produced random noise, hiding all structure.  
- Confirms CBC’s superiority in confidentiality.  

---

## ▶️ How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/HamedMusleh/AES-128-CBC-From-Scratch.git
   cd AES-128-CBC-From-Scratch
