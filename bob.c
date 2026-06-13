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
        if (sent <= 0) {
            fprintf(stderr, "send_all failed\n");
            return -1;
        }
        total += sent;
    }
    return 0;
}

int recv_all(int sock, void *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t rec = recv(sock, (char*)buffer + total, length - total, 0);
        if (rec <= 0) {
            fprintf(stderr, "recv_all failed\n");
            return -1;
        }
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

// ---------- HASH TO RISTRETTO POINT ----------

void hash_to_point(unsigned char out[32], const char *in) {

    unsigned char h[64];

    if (crypto_generichash(h, sizeof(h),
        (const unsigned char*)in,
        strlen(in),
        NULL, 0) != 0) {
        fprintf(stderr, "generichash failed\n");
        return;
    }

    if (crypto_core_ristretto255_from_hash(out, h) != 0) {
        fprintf(stderr, "ristretto hash-to-point failed\n");
        return;
    }
}

// ---------- DATA ----------

int read_dataset(const char *file, char set[][MAX_LINE]) {
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "file open failed\n");
        return -1;
    }

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

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "socket failed\n");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind failed\n");
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        fprintf(stderr, "listen failed\n");
        return 1;
    }

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        fprintf(stderr, "accept failed\n");
        return 1;
    }

    // ---------- SECRET ----------
    unsigned char b[32];
    randombytes_buf(b, 32);

    // ---------- DATA ----------
    char bob_set[MAX_ITEMS][MAX_LINE];

    int bob_size = read_dataset("bob_dataset.txt", bob_set);
    if (bob_size < 0) {
        fprintf(stderr, "dataset load failed\n");
        return 1;
    }

    unsigned char bob_blinded[MAX_ITEMS][32];

    // ---------- STEP 1: bH(y) ----------
    for (int i = 0; i < bob_size; i++) {

        unsigned char p[32];

        hash_to_point(p, bob_set[i]);

        if (crypto_scalarmult(bob_blinded[i], b, p) != 0) {
            fprintf(stderr, "bob blinding failed at %d\n", i);
            return 1;
        }
    }

    // ---------- STEP 2 RECEIVE ----------
    int alice_size;

    if (recv_int(client_fd, &alice_size) != 0) {
        fprintf(stderr, "recv alice_size failed\n");
        return 1;
    }

    if (alice_size <= 0 || alice_size > MAX_ITEMS) {
        fprintf(stderr, "invalid alice_size\n");
        return 1;
    }

    unsigned char alice_blinded[MAX_ITEMS][32];

    if (recv_all(client_fd, alice_blinded, alice_size * 32) != 0) {
        fprintf(stderr, "recv alice_blinded failed\n");
        return 1;
    }

    // ---------- STEP 3 COMPUTE ----------
    unsigned char alice_double[MAX_ITEMS][32];

    for (int i = 0; i < alice_size; i++) {

        if (crypto_scalarmult(alice_double[i], b, alice_blinded[i]) != 0) {
            fprintf(stderr, "alice double failed at %d\n", i);
            return 1;
        }
    }

    // ---------- STEP 4 SEND BACK ----------
    if (send_int(client_fd, bob_size) != 0) {
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

    // ---------- STEP 5 RECEIVE RESULT ----------
    int intersection_count;

    if (recv_int(client_fd, &intersection_count) != 0) {
        fprintf(stderr, "recv intersection_count failed\n");
        return 1;
    }

    if (intersection_count < 0 || intersection_count > MAX_ITEMS) {
        fprintf(stderr, "invalid intersection_count\n");
        return 1;
    }

    char intersection[MAX_ITEMS][MAX_LINE];

    for (int i = 0; i < intersection_count; i++) {

        int len;

        if (recv_int(client_fd, &len) != 0) {
            fprintf(stderr, "recv len failed\n");
            return 1;
        }

        if (len <= 0 || len >= MAX_LINE) {
            fprintf(stderr, "invalid string length\n");
            return 1;
        }

        if (recv_all(client_fd, intersection[i], len) != 0) {
            fprintf(stderr, "recv intersection item failed\n");
            return 1;
        }

        intersection[i][len] = '\0';
    }

    // ---------- OUTPUT ----------
    printf("\n----- Intersection (from Alice) -----\n");

    if (intersection_count == 0) {
        printf("No intersection found.\n");
    } else {
        for (int i = 0; i < intersection_count; i++) {
            printf("%s\n", intersection[i]);
        }
    }

    close(client_fd);
    close(server_fd);
    sodium_memzero(b, 32);

    return 0;
}
