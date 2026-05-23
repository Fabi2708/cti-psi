// ============================
// Bob (server)
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

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    unsigned char bob_private[32];
    randombytes_buf(bob_private, 32);

    char bob_set[MAX_ITEMS][MAX_LINE];
    int bob_size = read_dataset("bob_dataset.txt", bob_set);
    if (bob_size < 0) {
        fprintf(stderr, "dataset read failed\n");
        return 1;
    }

    unsigned char bob_blinded[MAX_ITEMS][32];

    for (int i = 0; i < bob_size; i++) {
        unsigned char p[32];
        hash_to_scalar(p, bob_set[i]);

        if (crypto_scalarmult(bob_blinded[i], bob_private, p) != 0) {
            fprintf(stderr, "crypto_scalarmult failed (bob_blinded)\n");
            return 1;
        }
    }

    int alice_size;
    if (recv_all(client_fd, &alice_size, sizeof(int)) != 0) {
        fprintf(stderr, "recv alice_size failed\n");
        return 1;
    }

    unsigned char alice_blinded[MAX_ITEMS][32];
    if (recv_all(client_fd, alice_blinded, alice_size * 32) != 0) {
        fprintf(stderr, "recv alice_blinded failed\n");
        return 1;
    }

    unsigned char alice_double[MAX_ITEMS][32];

    for (int i = 0; i < alice_size; i++) {
        if (crypto_scalarmult(alice_double[i], bob_private, alice_blinded[i]) != 0) {
            fprintf(stderr, "crypto_scalarmult failed (alice_double)\n");
            return 1;
        }
    }

    if (send_all(client_fd, &bob_size, sizeof(int)) != 0) {
        fprintf(stderr, "send bob_size failed\n");
        return 1;
    }

    if (send_all(client_fd, alice_double, alice_size * 32) != 0) {
        fprintf(stderr, "send alice_double failed\n");
        return 1;
    }

    if (send_all(client_fd, bob_blinded, bob_size * 32) != 0) {
        fprintf(stderr, "send bob_blinded failed\n");
        return 1;
    }

    printf("Done.\n");

    close(client_fd);
    close(server_fd);
    sodium_memzero(bob_private, 32);

    return 0;
}
