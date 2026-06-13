// ============================
// Alice (Client)
// ============================

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>

#define PORT 8080
#define MAX_ITEMS 400
#define MAX_LINE 256

// ---------- SAFE IO ----------

int send_all(int sock, const void *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t sent = send(sock, (const char*)buffer + total, length - total, 0);
        if (sent <= 0) return -1;
        total += sent;
    }
    return 0;
}

int recv_all(int sock, void *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t rec = recv(sock, (char*)buffer + total, length - total, 0);
        if (rec <= 0) return -1;
        total += rec;
    }
    return 0;
}

int send_int(int sock, int v) {
    int net = htonl(v);
    return send_all(sock, &net, sizeof(net));
}

int recv_int(int sock, int *v) {
    int net;
    if (recv_all(sock, &net, sizeof(net)) != 0) return -1;
    *v = ntohl(net);
    return 0;
}

// ---------- HASH ----------

void hash_to_scalar(unsigned char out[32], const char *in) {
    crypto_generichash(out, 32,
        (const unsigned char*)in,
        strlen(in),
        NULL, 0);

    out[0]  &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

// ---------- DATA ----------

int read_dataset(const char *file, char set[][MAX_LINE]) {
    FILE *f = fopen(file, "r");
    if (!f) return -1;

    int n = 0;
    while (fgets(set[n], MAX_LINE, f)) {
        set[n][strcspn(set[n], "\r\n")] = 0;
        if (strlen(set[n]) > 0) n++;
    }

    fclose(f);
    return n;
}

// ============================
// MAIN
// ============================

int main() {

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket failed\n");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "10.0.2.9", &addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed\n");
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }

    // ---------- SECRET ----------
    unsigned char a[32];
    randombytes_buf(a, 32);

    // ---------- DATA ----------
    char alice_set[MAX_ITEMS][MAX_LINE];
    int alice_size = read_dataset("alice_dataset.txt", alice_set);

    if (alice_size < 0) {
        fprintf(stderr, "dataset load failed\n");
        return 1;
    }

    unsigned char alice_blinded[MAX_ITEMS][32];

    // ---------- STEP 1 ----------
    for (int i = 0; i < alice_size; i++) {
        unsigned char h[32];
        hash_to_scalar(h, alice_set[i]);

        if (crypto_scalarmult(alice_blinded[i], a, h) != 0) {
            fprintf(stderr, "blinding failed\n");
            return 1;
        }
    }

    // ---------- STEP 2 SEND ----------
    if (send_int(sock, alice_size) != 0) {
        fprintf(stderr, "send alice_size failed\n");
        return 1;
    }

    if (send_all(sock, alice_blinded, alice_size * 32) != 0) {
        fprintf(stderr, "send alice_blinded failed\n");
        return 1;
    }

    // ---------- STEP 3 RECEIVE ----------
    int bob_size;

    if (recv_int(sock, &bob_size) != 0) {
        fprintf(stderr, "recv bob_size failed\n");
        return 1;
    }

    if (bob_size < 0 || bob_size > MAX_ITEMS) {
        fprintf(stderr, "invalid bob_size\n");
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

    // ---------- STEP 4 COMPUTE ----------
    unsigned char bob_double[MAX_ITEMS][32];

    for (int i = 0; i < bob_size; i++) {
        if (crypto_scalarmult(bob_double[i], a, bob_blinded[i]) != 0) {
            fprintf(stderr, "bob_double failed\n");
            return 1;
        }
    }

    // ---------- STEP 5 INTERSECTION ----------
    char intersection[MAX_ITEMS][MAX_LINE];
    int intersection_count = 0;
    int found = 0;

    for (int i = 0; i < alice_size; i++) {
        for (int j = 0; j < bob_size; j++) {
            if (memcmp(alice_double[i], bob_double[j], 32) == 0) {

                if (intersection_count >= MAX_ITEMS) {
                    fprintf(stderr, "intersection overflow\n");
                    return 1;
                }

                strcpy(intersection[intersection_count], alice_set[i]);
                intersection_count++;
                found = 1;
            }
        }
    }

    printf("\n----- Intersection -----\n");

    if (!found) {
        printf("No intersection found.\n");
    } else {
        for (int i = 0; i < intersection_count; i++) {
            printf("%s\n", intersection[i]);
        }
    }

    // ---------- STEP 6 SEND RESULT ----------
    if (send_int(sock, intersection_count) != 0) {
        fprintf(stderr, "send intersection_count failed\n");
        return 1;
    }

    for (int i = 0; i < intersection_count; i++) {

        int len = strlen(intersection[i]);

        if (send_int(sock, len) != 0) {
            fprintf(stderr, "send len failed\n");
            return 1;
        }

        if (send_all(sock, intersection[i], len) != 0) {
            fprintf(stderr, "send intersection item failed\n");
            return 1;
        }
    }

    close(sock);
    sodium_memzero(a, 32);

    return 0;
}
