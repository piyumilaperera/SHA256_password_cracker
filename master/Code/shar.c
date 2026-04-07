#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
#endif

#define MAX_THREADS  16
#define BATCH_SIZE   50000


typedef struct {
    char*  data;
    size_t len;
    char   _pad[48];
} PasswordEntry;

static PasswordEntry*      password_list      = NULL;
static char*               file_buffer        = NULL;
static size_t              file_buffer_size   = 0;
static int                 use_mmap           = 0;
static unsigned long long  total_passwords    = 0;

static char           input_hash[65];
static unsigned char  byte_hash[32];

static atomic_int          found              = 0;
static atomic_ullong       global_worker_idx  = 0;

static EVP_MD* g_md = NULL;

static void  load_file_to_mem(const char* filename);
static void* worker(void* arg);
static void  buffercleaner(void);
static void  clean(void);
static void  print_banner(void);
static void  hex_to_byte(void);

int main(void)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    clean();

    g_md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (!g_md) {
        fprintf(stderr, "[-] Failed to fetch SHA-256 from OpenSSL provider.\n");
        return 1;
    }

    char filename[256];
    while (1) {
        printf("\n[+] Enter the path of the dictionary : ");
        if (fgets(filename, sizeof(filename), stdin) == NULL) continue;
        filename[strcspn(filename, "\n")] = '\0';

        if (strcmp(filename, "exit") == 0) { EVP_MD_free(g_md); exit(0); }

        FILE* tmp = fopen(filename, "r");
        if (tmp) { fclose(tmp); break; }
        printf("[-] Invalid file path.\n");
    }

    while (1) {
        printf("\n[+] Enter the SHA-256 hash value: ");
        if (fgets(input_hash, sizeof(input_hash), stdin) == NULL) continue;
        if (input_hash[strlen(input_hash) - 1] != '\n') buffercleaner();
        input_hash[strcspn(input_hash, "\n")] = '\0';

        if (strlen(input_hash) == 64) break;
        printf("[-] Invalid hash length. Must be 64 hex characters.\n");
    }

    hex_to_byte();

    printf("[*] Loading dictionary into memory...\n");
    load_file_to_mem(filename);
    printf("[*] Loaded %llu passwords. Starting %d threads...\n",
           total_passwords, MAX_THREADS);

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    pthread_t threads[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; i++)
        pthread_create(&threads[i], NULL, worker, NULL);

    for (int i = 0; i < MAX_THREADS; i++)
        pthread_join(threads[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    if (!atomic_load(&found))
        printf("\n[-] Password not found in dictionary.\n");

    double elapsed = (ts_end.tv_sec  - ts_start.tv_sec)
                   + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
    printf("\n[*] Total time taken = %.4f seconds\n", elapsed);


    EVP_MD_free(g_md);

#ifndef _WIN32
    if (use_mmap)
        munmap(file_buffer, file_buffer_size);
    else
        free(file_buffer);
#else
    free(file_buffer);
#endif
    free(password_list);

    return 0;
}


static void* worker(void* arg)
{
    (void)arg;

    unsigned char local_hash[32];
    unsigned int  hash_len = 32;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;

    while (!atomic_load_explicit(&found, memory_order_relaxed)) {


        unsigned long long start_idx =
            atomic_fetch_add_explicit(&global_worker_idx, BATCH_SIZE,
                                      memory_order_relaxed);
        if (start_idx >= total_passwords) break;

        unsigned long long end_idx = start_idx + BATCH_SIZE;
        if (end_idx > total_passwords) end_idx = total_passwords;


        for (unsigned long long i = start_idx; i < end_idx; i++) {

            EVP_DigestInit_ex(ctx, g_md, NULL);
            EVP_DigestUpdate(ctx, password_list[i].data, password_list[i].len);
            EVP_DigestFinal_ex(ctx, local_hash, &hash_len);

            if (memcmp(local_hash, byte_hash, 32) == 0) {
                printf("\n[++++++] Password found : %s\n", password_list[i].data);
                atomic_store(&found, 1);
                EVP_MD_CTX_free(ctx);
                return NULL;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    return NULL;
}


static void load_file_to_mem(const char* filename)
{
    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "[-] stat() failed on file.\n");
        return;
    }

    FILE* f = fopen(filename, "rb");
    if (!f) { fprintf(stderr, "[-] Cannot open file.\n"); return; }

#ifndef _WIN32

    file_buffer_size = (size_t)st.st_size;
    file_buffer = mmap(NULL, file_buffer_size,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(f), 0);
    fclose(f);
    if (file_buffer == MAP_FAILED) {
        file_buffer = malloc((size_t)st.st_size + 1);
        f = fopen(filename, "rb");
        fread(file_buffer, 1, (size_t)st.st_size, f);
        fclose(f);
        file_buffer[st.st_size] = '\0';
        use_mmap = 0;
    } else {
 
        use_mmap = 1;
    }
#else
    file_buffer = malloc((size_t)st.st_size + 1);
    fread(file_buffer, 1, (size_t)st.st_size, f);
    fclose(f);
    file_buffer[st.st_size] = '\0';
#endif


    unsigned long long lines = 0;
    {
        char* p   = file_buffer;
        char* end = file_buffer + st.st_size;
        while ((p = memchr(p, '\n', (size_t)(end - p))) != NULL) { lines++; p++; }
    }

    password_list = malloc(sizeof(PasswordEntry) * (lines + 1));
    if (!password_list) { fprintf(stderr, "[-] malloc failed.\n"); return; }


    unsigned long long current_pwd = 0;
    char* line = file_buffer;

    for (long long i = 0; i < st.st_size; i++) {
        char c = file_buffer[i];
        if (c == '\n' || c == '\r') {
            // Length via pointer arithmetic — avoids second strlen pass
            size_t len = (size_t)(&file_buffer[i] - line);
            if (len > 0) {
                password_list[current_pwd].data = line;
                password_list[current_pwd].len  = len;
                current_pwd++;
            }
            file_buffer[i] = '\0';
            line = &file_buffer[i + 1];
        }
    }


    size_t last_len = (size_t)(file_buffer + st.st_size - line);
    if (last_len > 0) {
        password_list[current_pwd].data = line;
        password_list[current_pwd].len  = last_len;
        current_pwd++;
    }

    total_passwords = current_pwd;
}

static void hex_to_byte(void)
{
    for (int i = 0; i < 32; i++) {
        char hex[3] = { input_hash[i * 2], input_hash[i * 2 + 1], '\0' };
        byte_hash[i] = (unsigned char)strtol(hex, NULL, 16);
    }
}

static void buffercleaner(void)
{
    int x;
    while ((x = getchar()) != '\n' && x != EOF);
}

static void clean(void)
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
    print_banner();
}

static void print_banner(void)
{
    printf("                    ███████╗██╗  ██╗ █████╗ ██████╗  \n");
    printf("                    ██╔════╝██║  ██║██╔══██╗██╔══██╗ \n");
    printf("                    ███████╗███████║███████║██████╔╝ \n");
    printf("                    ╚════██║██╔══██║██╔══██║██╔══██╗ \n");
    printf("                    ███████║██║  ██║██║  ██║██║  ██║ \n");
    printf("                    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ \n");
    printf("\n");
    printf("   Very Simple, Efficient, Multi threaded CPU based SHA-256 Dictionary Cracker By Piyumila Perera\n");
    printf("   Educational Use Only\n");
    printf("   Version 2.0.0\n\n");
}