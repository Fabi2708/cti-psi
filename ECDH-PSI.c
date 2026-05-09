#include <stdio.h>
#include <string.h>
#include <sodium.h>

// Elliptic Curve Diffie-Hellman PSI using X25519
int main() {
    if (sodium_init() < 0) {
        printf("Libsodium initialisation failed.\n");
        return 1;
    }

    // ----- 1. Generate private keys -----
    unsigned char alice_private[32], bob_private[32];
    randombytes_buf(alice_private, sizeof(alice_private));
    randombytes_buf(bob_private, sizeof(bob_private));

    char hex[65];
    sodium_bin2hex(hex, sizeof(hex), alice_private, 32);
    printf("Alice private key: %s\n", hex);
    sodium_bin2hex(hex, sizeof(hex), bob_private, 32);
    printf("Bob private key: %s\n", hex);

    // ----- 2. Define sets -----
    const char *alice_set[] = {"A", "B", "C"};
    int alice_size = 3;
    const char *bob_set[] = {"B", "C", "D"};
    int bob_size = 3;

    unsigned char hash[32];

    // ----- 3. Alice blinds her set -----
    unsigned char alice_blinded[alice_size][32];
    printf("\n-----Alice blinding her set-----\n");
    for (int i = 0; i < alice_size; i++) {
        const char *m = alice_set[i];
        printf("Processing: %s\n", m);

        // Hash element to 32 bytes
        crypto_generichash(hash, sizeof(hash), (unsigned char *)m, strlen(m), NULL, 0);

        // Scalar multiply hash with Alice's private key
        if (crypto_scalarmult(alice_blinded[i], alice_private, hash) != 0) {
            printf("Error for element %s\n", m);
            return 1;
        }

        char result_hex[65];
        sodium_bin2hex(result_hex, sizeof(result_hex), alice_blinded[i], 32);
        printf("Blinded(%s)^a: %s\n", m, result_hex);
    }

    // ----- 4. Bob blinds his set -----
    unsigned char bob_blinded[bob_size][32];
    printf("\n-----Bob blinding his set-----\n");
    for (int i = 0; i < bob_size; i++) {
        const char *m = bob_set[i];
        printf("Processing: %s\n", m);

        crypto_generichash(hash, sizeof(hash), (unsigned char *)m, strlen(m), NULL, 0);

        if (crypto_scalarmult(bob_blinded[i], bob_private, hash) != 0) {
            printf("Error for element %s\n", m);
            return 1;
        }

        char result_hex[65];
        sodium_bin2hex(result_hex, sizeof(result_hex), bob_blinded[i], 32);
        printf("Blinded(%s)^b: %s\n", m, result_hex);
    }

    // ----- 5. Alice double-blinds Bob's set -----
    unsigned char alice_double[bob_size][32];
    for (int i = 0; i < bob_size; i++) {
        if (crypto_scalarmult(alice_double[i], alice_private, bob_blinded[i]) != 0) {
            printf("Error double-blinding Bob element %d\n", i);
            return 1;
        }
    }

    // ----- 6. Bob double-blinds Alice's set -----
    unsigned char bob_double[alice_size][32];
    for (int i = 0; i < alice_size; i++) {
        if (crypto_scalarmult(bob_double[i], bob_private, alice_blinded[i]) != 0) {
            printf("Error double-blinding Alice element %d\n", i);
            return 1;
        }
    }

    // ----- 7. Compare for intersection -----
    printf("\n-----Intersection-----\n");
    for (int i = 0; i < bob_size; i++) { // iterate Bob's original set
        for (int j = 0; j < alice_size; j++) { // iterate Alice's original set
            if (memcmp(alice_double[i], bob_double[j], 32) == 0) {
                printf("Intersection found: %s\n", bob_set[i]);
            }
        }
    }

    // ----- 8. Erase sensitive data -----
    sodium_memzero(alice_private, sizeof(alice_private));
    sodium_memzero(bob_private, sizeof(bob_private));

    return 0;
}
