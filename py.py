from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

def aes_encrypt_ecb(message: str, key: bytes) -> str:
    """
    Encrypt a message using AES (ECB mode) and return the encrypted message as a hexadecimal string.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def aes_decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Définition de la clé AES
key = b"sokhnandeyehabib"  # Clé AES de 16 octets pour AES-128

# Exemple d'utilisation avec une clé définie par l'utilisateur
plaintext = "Fatou"

# Chiffrement
ciphertext = aes_encrypt_ecb(plaintext, key)
print(ciphertext.hex())


# Déchiffrement
# decrypted_plaintext = aes_decrypt_ecb(ciphertext, key)
# print("Decrypted plaintext:", decrypted_plaintext.decode('utf-8'))



# #include <stdio.h>
# #include <openssl/aes.h>

# void aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
#     AES_KEY aes_key;
#     AES_set_decrypt_key(key, 128, &aes_key);
#     AES_cfb128_decrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, NULL);
# }

# int main() {
#     unsigned char key[] = "0123456789abcdef"; // 16 bytes for AES-128
#     unsigned char ciphertext[] = {0x1a, 0xb2, 0x63, 0xea, 0x0b, 0xe5, 0xe2, 0x7d, 0x08, 0x8b, 0xca, 0x48, 0x09, 0xfb, 0x59, 0x73};
#     unsigned char iv[16];
#     unsigned char plaintext[16];

#     // Extract IV from ciphertext
#     memcpy(iv, ciphertext, 16);

#     // Decrypt ciphertext (excluding IV)
#     aes_decrypt(ciphertext + 16, sizeof(ciphertext) - 16, key, iv, plaintext);

#     printf("Deciphered text: %s\n", plaintext);

#     return 0;
# }


