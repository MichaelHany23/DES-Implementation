/*
  DES ECB encrypt/decrypt tool (single source file).
  Usage:
    studentID "e" keyfile plaintextfile ciphertextfile
    studentID "d" keyfile ciphertextfile plaintextfile

  - keyfile: binary file containing 8 bytes (64-bit DES key, big-endian)
  - input/output files are processed in 8-byte blocks (ECB). Message size is assumed
    to be a multiple of 8 bytes (no padding).
  - Uses fopen/fread/fwrite/fclose as required.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ─────────────────────── DES TABLES  ─────────────────────── */
/* Tables from the DES specification (kept as int arrays). */

static const int IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const int PC1_TABLE[56] = {
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};

static const int PC2_TABLE[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};

static const int shifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static const int expansion[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
};

static const int permutation[32] = {
    16,7,20,21,29,12,28,17,
     1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

static const int inverse_IP[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

static const int S_BOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

/* ─────────────────────── Utility Functions  ─────────────────────── */

/* Permutation helper:
   - table entries are 1-based positions counting from MSB (left).
   - nbits_input tells how many meaningful bits are in 'input'. */
static uint64_t permute(uint64_t input, const int* table, int nbits_out, int nbits_input)
{
    uint64_t output = 0ULL;
    for (int i = 0; i < nbits_out; i++) {
        int src_pos = nbits_input - table[i];
        uint64_t bit = (input >> src_pos) & 0x01ULL;
        output = (output << 1) | bit;
    }
    return output;
}

/* Left circular shift for 28-bit halves */
static uint32_t leftCircularshift(uint32_t input, int n)
{
    return ((input << n) | (input >> (28 - n))) & 0x0FFFFFFF;
}

/* Apply all S-boxes: input is 48-bit value in low 48 bits of uint64_t */
static uint32_t s_box(uint64_t input)
{
    uint32_t output = 0;
    for (int i = 0; i < 8; i++) {
        uint16_t chunk = (input >> (42 - i * 6)) & 0x3F; /* left-to-right extraction */
        int row = (chunk & 0x20 ? 2 : 0) | (chunk & 0x01); /* b5 b0 -> row */
        int col = (chunk >> 1) & 0xF;
        output |= (uint32_t)S_BOX[i][row][col] << (28 - i * 4);
    }
    return output;
}

/* Feistel F-function: input 32-bit, subkey 48-bit (in low 48 bits of uint64_t) */
static uint32_t feistel(uint32_t input, uint64_t subkey)
{
    uint64_t expanded = permute(input, expansion, 48, 32); /* expand to 48 bits */
    expanded ^= subkey;
    uint32_t after_s = s_box(expanded);
    return (uint32_t)permute(after_s, permutation, 32, 32);
}

/* DES single-block processor.
   - decrypt = 0 for encryption, non-zero for decryption.
   Implements key schedule once and runs 16 rounds; for decryption it uses
   subkeys in reverse order. */
static uint64_t DES_process_block(uint64_t block, uint64_t key, int decrypt)
{
    /* Initial permutation */
    uint64_t ip = permute(block, IP, 64, 64);

    /* Key schedule: PC-1 */
    uint64_t pc1 = permute(key, PC1_TABLE, 56, 64);
    uint32_t C = (uint32_t)((pc1 >> 28) & 0x0FFFFFFF);
    uint32_t D = (uint32_t)(pc1 & 0x0FFFFFFF);

    uint64_t subkeys[17]; /* 1..16 used */
    for (int i = 1; i <= 16; i++) {
        C = leftCircularshift(C, shifts[i-1]);
        D = leftCircularshift(D, shifts[i-1]);
        subkeys[i] = permute(((uint64_t)C << 28) | (uint64_t)D, PC2_TABLE, 48, 56);
    }

    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFFU);

    /* 16 Feistel rounds */
    if (!decrypt) {
        for (int i = 1; i <= 16; i++) {
            uint32_t temp = R;
            R = L ^ feistel(R, subkeys[i]);
            L = temp;
        }
    } else {
        for (int i = 16; i >= 1; i--) {
            uint32_t temp = R;
            R = L ^ feistel(R, subkeys[i]);
            L = temp;
        }
    }

    /* Preoutput: R16 || L16 (swap) then inverse IP */
    uint64_t pre = ((uint64_t)R << 32) | (uint64_t)L;
    return permute(pre, inverse_IP, 64, 64);
}

/* Convert 8 bytes (big-endian) to uint64_t */
static uint64_t bytes_to_u64_be(const uint8_t *b)
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}

/* Write uint64_t to 8 bytes (big-endian) */
static void u64_to_bytes_be(uint64_t v, uint8_t *b)
{
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

/* Read exactly 8 bytes from file into buf; returns 1 on success, 0 on EOF, -1 on error */
static int fread_block(FILE *f, uint8_t *buf)
{
    size_t n = fread(buf, 1, 8, f);
    if (n == 8) return 1;
    if (n == 0) return 0; /* EOF */
    /* Partial read: treat as error because problem states file size is multiple of block size */
    return -1;
}

/* Main: required signature */
int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s \"e|d\" keyfile infile outfile\n", argv[0]);
        return 1;
    }

    int decrypt = 0;
    if (strcmp(argv[1], "e") == 0) decrypt = 0;
    else if (strcmp(argv[1], "d") == 0) decrypt = 1;
    else {
        fprintf(stderr, "First argument must be \"e\" or \"d\"\n");
        return 1;
    }

    /* Open key file and read 8 bytes */
    FILE *fk = fopen(argv[2], "rb");
    if (!fk) { perror("fopen keyfile"); return 1; }
    uint8_t keybuf[8];
    if (fread(keybuf, 1, 8, fk) != 8) { fclose(fk); fprintf(stderr, "Failed to read 8-byte key\n"); return 1; }
    fclose(fk);
    uint64_t key = bytes_to_u64_be(keybuf);

    /* Open input and output files */
    FILE *fin = fopen(argv[3], "rb");
    if (!fin) { perror("fopen infile"); return 1; }
    FILE *fout = fopen(argv[4], "wb");
    if (!fout) { perror("fopen outfile"); fclose(fin); return 1; }

    /* Process in a moderate buffer for speed: read many blocks per fread/fwrite */
    const size_t BUF_SIZE = 1 << 14; /* 16 KB, multiple of 8 */
    uint8_t *ibuf = (uint8_t*)malloc(BUF_SIZE);
    if (!ibuf) { fprintf(stderr, "malloc failed\n"); fclose(fin); fclose(fout); return 1; }

    while (1) {
        size_t got = fread(ibuf, 1, BUF_SIZE, fin);
        if (got == 0) break;
        if (got % 8 != 0) {
            /* According to spec this should not happen */
            fprintf(stderr, "Input size not multiple of 8 bytes\n");
            free(ibuf);
            fclose(fin);
            fclose(fout);
            return 1;
        }
        /* Process each 8-byte block in buffer */
        for (size_t off = 0; off < got; off += 8) {
            uint64_t blk = bytes_to_u64_be(ibuf + off);
            uint64_t outblk = DES_process_block(blk, key, decrypt);
            uint8_t outb[8];
            u64_to_bytes_be(outblk, outb);
            if (fwrite(outb, 1, 8, fout) != 8) {
                perror("fwrite");
                free(ibuf);
                fclose(fin);
                fclose(fout);
                return 1;
            }
        }
        if (got < BUF_SIZE) break; /* EOF reached */
    }

    free(ibuf);
    fclose(fin);
    fclose(fout);
    return 0;
}