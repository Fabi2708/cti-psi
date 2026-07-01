#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <time.h>

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

double elapsed_ms(struct timespec start, struct timespec end){
    return(end.tv_sec - start.tv_sec) * 1000.0 +
          (end.tv_nsec - start.tv_nsec) / 1000000.0;  
}

typedef struct{
    int dataset_size;
    double hash_ms;
    double blind_ms;
    double double_blind_ms;
    double send_ms;
    double recv_ms;
    double intersection_ms;
    double total_ms;
}Metrics;
// ============================
// MAIN
// ============================

int main() {

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    Metrics alice = {0};
    alice.dataset_size = 0;
    struct timespec start, end, total_start,total_end;
    
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
    alice.dataset_size = alice_size;
    clock_gettime(CLOCK_MONOTONIC, &total_start);
    
    unsigned char alice_blinded[MAX_ITEMS][32];

    // ---------- STEP 1: aH(x) ----------
    for (int i = 0; i < alice_size; i++) {

        unsigned char p[32];

        clock_gettime(CLOCK_MONOTONIC, &start);
        hash_to_point(p, alice_set[i]);
        clock_gettime(CLOCK_MONOTONIC,&end);
        alice.hash_ms += elapsed_ms(start,end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (crypto_scalarmult(alice_blinded[i], a, p) != 0) {
            fprintf(stderr, "alice blinding failed at %d\n", i);
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC,&end);
        alice.blind_ms += elapsed_ms(start,end);
    }

    // ---------- STEP 2 SEND ----------
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (send_int(sock, alice_size) != 0) {
        fprintf(stderr, "send alice_size failed\n");
        return 1;
    }

    if (send_all(sock, alice_blinded, alice_size * 32) != 0) {
        fprintf(stderr, "send alice_blinded failed\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC,&end);
    alice.send_ms += elapsed_ms(start,end);

    // ---------- STEP 3 RECEIVE ----------
    int bob_size;

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (recv_int(sock, &bob_size) != 0) {
        fprintf(stderr, "recv bob_size failed\n");
        return 1;
    }

    if (bob_size <= 0 || bob_size > MAX_ITEMS) {
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
    clock_gettime(CLOCK_MONOTONIC,&end);
    alice.recv_ms += elapsed_ms(start,end);
    // ---------- STEP 4 COMPUTE ----------
    unsigned char bob_double[MAX_ITEMS][32];

    for (int i = 0; i < bob_size; i++) {
        clock_gettime(CLOCK_MONOTONIC,&start);
        if (crypto_scalarmult(bob_double[i], a, bob_blinded[i]) != 0) {
            fprintf(stderr, "bob double failed at %d\n", i);
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC,&end);
        alice.double_blind_ms += elapsed_ms(start,end);
    }

    // ---------- STEP 5 INTERSECTION ----------
    char intersection[MAX_ITEMS][MAX_LINE];
    int intersection_count = 0;
    int found = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
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
    clock_gettime(CLOCK_MONOTONIC,&end);
    alice.intersection_ms += elapsed_ms(start,end);

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
    Metrics bob;
     if (recv_all(sock, &bob, sizeof(Metrics)) != 0) {
        fprintf(stderr, "recv bob_blinded failed\n");
        return 1;
    }
    close(sock);
    sodium_memzero(a, 32);
    clock_gettime(CLOCK_MONOTONIC,&total_end);
    alice.total_ms += elapsed_ms(total_start,total_end);

    FILE *csv = fopen("results.csv", "a");
    if(csv == NULL){
        fprintf(stderr, "failed to open csv\n");
        return 1;
    }
    fseek(csv, 0, SEEK_END);
    long size = ftell(csv);
    if (size == 0) {
    fprintf(csv,
        "dataset_size,"
        "alice_hash,alice_blind,alice_double_blind,alice_send,alice_recv,alice_intersection,alice_total,"
        "bob_hash,bob_blind,bob_double_blind,bob_send,bob_recv,bob_intersection,bob_total\n");
    }

    fprintf(csv,
    "%d,"
    "%f,%f,%f,%f,%f,%f,%f,"
    "%f,%f,%f,%f,%f,%f,%f\n",
    
    alice.dataset_size,
    
    alice.hash_ms,
    alice.blind_ms,
    alice.double_blind_ms,
    alice.send_ms,
    alice.recv_ms,
    alice.intersection_ms,
    alice.total_ms,
    
    bob.hash_ms,
    bob.blind_ms,
    bob.double_blind_ms,
    bob.send_ms,
    bob.recv_ms,
    bob.intersection_ms,
    bob.total_ms);
    
    fclose(csv);

    return 0;
}
