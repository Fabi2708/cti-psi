// ============================
// Alice (client)
// ============================

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>

#define PORT 8080
#define MAX_ITEMS 400
#define MAX_LINE 256

int read_dataset(const char *filename, char dataset[][MAX_LINE]) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    int count = 0;
    while (fgets(dataset[count], MAX_LINE, file)) {
        dataset[count][strcspn(dataset[count], "\r\n")] = 0;
        if (strlen(dataset[count]) > 0) count++;
    }

    fclose(file);
    return count;
}

int send_all(int sock, const void *buffer, size_t length) {
    size_t total = 0;

    while (total < length) {
        ssize_t sent = send(sock, (const char*)buffer + total, length - total, 0);
        if (sent <= 0) return -1;
        total += (size_t)sent;
    }

    return 0;
}

int recv_all(int sock, void *buffer, size_t length) {
    size_t total = 0;

    while (total < length) {
        ssize_t rec = recv(sock, (char*)buffer + total, length - total, 0);
        if (rec <= 0) return -1;
        total += (size_t)rec;
    }

    return 0;
}

void hash_to_scalar(unsigned char out[32], const char *in) {
    crypto_generichash(out, 32,
        (const unsigned char*)in,
        strlen(in),
        NULL, 0);

    out[0]  &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "10.0.2.9", &server_addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed\n");
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }

    unsigned char alice_private[32];
    randombytes_buf(alice_private, 32);

    char alice_set[MAX_ITEMS][MAX_LINE];
    int alice_size = read_dataset("alice_dataset.txt", alice_set);
    if (alice_size < 0) {
        fprintf(stderr, "failed to read dataset\n");
        return 1;
    }

    unsigned char alice_blinded[MAX_ITEMS][32];

    for (int i = 0; i < alice_size; i++) {
        unsigned char p[32];
        hash_to_scalar(p, alice_set[i]);

        if (crypto_scalarmult(alice_blinded[i], alice_private, p) != 0) {
            fprintf(stderr, "crypto_scalarmult failed (alice_blinded)\n");
            return 1;
        }
    }

    if (send_all(sock, &alice_size, sizeof(int)) != 0) {
        fprintf(stderr, "send alice_size failed\n");
        return 1;
    }

    if (send_all(sock, alice_blinded, alice_size * 32) != 0) {
        fprintf(stderr, "send alice_blinded failed\n");
        return 1;
    }

    int bob_size;
    if (recv_all(sock, &bob_size, sizeof(int)) != 0) {
        fprintf(stderr, "recv bob_size failed\n");
        return 1;
    }

    unsigned char alice_double[MAX_ITEMS][32];
    unsigned char bob_blinded[MAX_ITEMS][32];

    if (recv_all(sock, alice_double, alice_size * 32) != 0) {
        fprintf(stderr, "recv alice_double failed\n");
        return 1;
    }

    if (recv_all(sock, bob_blinded, bob_size * 32) != 0) {
        fprintf(stderr, "recv bob_blinded failed\n");
        return 1;
    }

    unsigned char bob_double[MAX_ITEMS][32];

    for (int i = 0; i < bob_size; i++) {
        if (crypto_scalarmult(bob_double[i], alice_private, bob_blinded[i]) != 0) {
            fprintf(stderr, "crypto_scalarmult failed (bob_double)\n");
            return 1;
        }
    }

    printf("\n----- Intersection -----\n");

    int found = 0;
    for (int i = 0; i < alice_size; i++) {
        for (int j = 0; j < bob_size; j++) {
            if (memcmp(alice_double[i], bob_double[j], 32) == 0) {
                printf("Intersection found: %s\n", alice_set[i]);
                found = 1;
            }
        }
    }

    if (!found) printf("No intersection found.\n");

    close(sock);
    sodium_memzero(alice_private, 32);

    return 0;
}
