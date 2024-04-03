#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/openssl/aes.h>
#include <wolfssl/openssl/evp.h>

void hexstr_to_bytes(const char *hexstr, unsigned char *bytes) {
    int i;
    for (i = 0; i < strlen(hexstr) / 2; ++i) {
        sscanf(hexstr + 2*i, "%2hhx", &bytes[i]);
    }
}

void aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_cfb128_decrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, NULL);
}

int main() {
    unsigned char key[] = "0123456789abcdef"; // 16 bytes for AES-128
    const char *hex_ciphertext = "1f9eb72b21c0215b2bac774032c9c23ef0bc021d8b0c94ec109244f350";
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[32]; // La taille de votre texte chiffré en bytes
    unsigned char plaintext[32]; // Taille du texte en clair

    // Convertir la chaîne hexadécimale en tableau d'octets
    hexstr_to_bytes(hex_ciphertext, ciphertext);

    // Extraire IV du texte chiffré
    memcpy(iv, ciphertext, AES_BLOCK_SIZE);

    // Déchiffrer le texte chiffré (à l'exception de IV)
    aes_decrypt(ciphertext + AES_BLOCK_SIZE, strlen(hex_ciphertext) / 2 - AES_BLOCK_SIZE, key, iv, plaintext);

    printf("Deciphered text: %s\n", plaintext);

    return 0;
}
