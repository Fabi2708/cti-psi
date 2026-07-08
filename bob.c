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
    size_t communication_sent;
    size_t communication_received;
}Metrics;

typedef struct{
    int size;
    int overlap;
    int stop;
}TestInfo;

size_t bytes_sent = 0;
size_t bytes_recv = 0;
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

    while(1){
        bytes_sent = 0;
        bytes_recv = 0;
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            fprintf(stderr, "accept failed\n");
            return 1;
        }
        TestInfo info;
        recv_int(client_fd, &info.size);
        recv_int(client_fd,&info.overlap);
        // ---------- SECRET ----------
        unsigned char b[32];
        randombytes_buf(b, 32);

        Metrics bob = {0};
        bob.dataset_size = 0;
        struct timespec start, end, total_start,total_end;

        // ---------- DATA ----------
        char bob_set[MAX_ITEMS][MAX_LINE];
        char filename[100];
        sprintf(filename, "datasets/bob_%d_%d.txt", info.size,info.overlap);

        int bob_size = read_dataset(filename, bob_set);
        if (bob_size < 0) {
            fprintf(stderr, "dataset load failed\n");
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &total_start);
        bob.dataset_size = bob_size;
        unsigned char bob_blinded[MAX_ITEMS][32];

        // ---------- STEP 1: bH(y) ----------
        for (int i = 0; i < bob_size; i++) {

            unsigned char p[32];

            clock_gettime(CLOCK_MONOTONIC, &start);
            hash_to_point(p, bob_set[i]);
            clock_gettime(CLOCK_MONOTONIC,&end);
            bob.hash_ms += elapsed_ms(start,end);

            clock_gettime(CLOCK_MONOTONIC, &start);
            if (crypto_scalarmult(bob_blinded[i], b, p) != 0) {
                fprintf(stderr, "bob blinding failed at %d\n", i);
                return 1;
            }
            clock_gettime(CLOCK_MONOTONIC,&end);
            bob.blind_ms += elapsed_ms(start,end);
        }

        // ---------- STEP 2 RECEIVE ----------
        int alice_size;
        clock_gettime(CLOCK_MONOTONIC, &start);
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
        bytes_recv += sizeof(int);
        bytes_recv += alice_size * 32;
        clock_gettime(CLOCK_MONOTONIC,&end);
        bob.recv_ms += elapsed_ms(start,end);

        // ---------- STEP 3 COMPUTE ----------
        unsigned char alice_double[MAX_ITEMS][32];

        for (int i = 0; i < alice_size; i++) {
            clock_gettime(CLOCK_MONOTONIC,&start);
            if (crypto_scalarmult(alice_double[i], b, alice_blinded[i]) != 0) {
                fprintf(stderr, "alice double failed at %d\n", i);
                return 1;
            }
            clock_gettime(CLOCK_MONOTONIC,&end);
            bob.double_blind_ms += elapsed_ms(start,end);
        }

        // ---------- STEP 4 SEND BACK ----------
        clock_gettime(CLOCK_MONOTONIC, &start);
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
        bytes_sent += sizeof(int);
        bytes_sent += alice_size * 32;
        bytes_sent += bob_size * 32;
        clock_gettime(CLOCK_MONOTONIC,&end);
        bob.send_ms += elapsed_ms(start,end);

        // ---------- STEP 5 RECEIVE RESULT ----------
        int intersection_count;
        clock_gettime(CLOCK_MONOTONIC, &start);
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
        clock_gettime(CLOCK_MONOTONIC,&end);
        bob.intersection_ms += elapsed_ms(start,end);
        // ---------- OUTPUT ----------
        printf("\n----- Intersection (from Alice) -----\n");

        if (intersection_count == 0) {
            printf("No intersection found.\n");
        } else {
            for (int i = 0; i < intersection_count; i++) {
                printf("%s\n", intersection[i]);
            }
        }
        clock_gettime(CLOCK_MONOTONIC,&total_end);
        bob.total_ms += elapsed_ms(total_start,total_end);
        //---------- Send Metrics ----------
        bob.communication_sent = bytes_sent;
        bob.communication_received = bytes_recv;
        if(send_all(client_fd, &bob ,sizeof(Metrics)) != 0){
            fprintf(stderr, "send bob metrics failed\n");
            return 1;
        }
        recv_int(client_fd, &info.stop);
        if(info.stop == 1){
            printf("Stopping server...\n");
            close(client_fd);
            break;
        }
        close(client_fd);
        sodium_memzero(b, 32);

    }
    close(server_fd);
    return 0;
}
