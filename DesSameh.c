/*
  Simple DES implementation (single-block encryption).
  I added plain-English comments to make the code easier to read.
  The code implements standard DES tables, key schedule, Feistel rounds,
  and encrypts two example 64-bit blocks in main().
*/
#include <stdio.h>
#include <stdint.h>

/* ─────────────────────── DES TABLES  ─────────────────────── */
/* These tables come straight from the DES specification.
   They are fixed lookup tables used throughout the algorithm. */

/* Initial Permutation (IP) table: rearranges bits of the plaintext block */
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

/* Permuted Choice 1 (PC-1): drop parity bits and split key into C and D */
static const int PC1_TABLE[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

/* Permuted Choice 2 (PC-2): compress C||D into a 48-bit subkey */
static const int PC2_TABLE[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};

/* How many left shifts to do on the C and D halves for each round */
static const int shifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

/* Expansion table: expands 32-bit R to 48 bits so it can be xored with subkey */
static const int expansion[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
};

/* P-permutation: applied after S-box substitution to diffuse bits */
static const int permutation[32] = {
    16,7,20,21,29,12,28,17,
     1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

/* Inverse of the initial permutation (IP^-1) used to form final ciphertext */
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

/* S-boxes: each S-box maps 6 bits to 4 bits. There are 8 S-boxes. */
static const int S_BOX[8][4][16] = {
    // S1
    {
        {14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},
        { 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
        { 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
        {15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13}
    },
    // S2
    {
        {15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},
        { 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
        { 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
        {13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9}
    },
    // S3
    {
        {10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
        {13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
        { 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12}
    },
    // S4
    {
        { 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},
        {13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
        {10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
        { 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14}
    },
    // S5
    {
        { 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},
        {14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
        { 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
        {11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3}
    },
    // S6
    {
        {12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},
        {10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
        { 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
        { 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13}
    },
    // S7
    {
        { 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},
        {13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6},
        { 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
        { 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12}
    },
    // S8
    {
        {13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},
        { 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
        { 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
        { 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}
    }
};

/* ─────────────────────── Utility Functions  ─────────────────────── */

/* Print a 64-bit number in hex with leading zeros.
   Using unsigned long long in printf keeps it portable across compilers. */
static void show_hex(uint64_t num) {
    printf("0x%016llX\n", (unsigned long long)num);
}

/* General bit permutation helper.
   - input: value whose bits we read
   - table: array of 1-based positions (from MSB side) telling which input bit goes next
   - nbits_out: how many bits to produce
   - nbits_input: how many bits are meaningful in input (used to calculate offsets)
   This function builds the output from MSB to LSB by reading the specified input bits. */
static uint64_t permute(uint64_t input, const int* table, int nbits_out, int nbits_input)
{
    uint64_t output = 0ULL;
    for (int i = 0; i < nbits_out; i++) {
        /* table entries are 1-based and count from the left (MSB),
           so compute the zero-based source position from the right-hand shift. */
        int src_pos = nbits_input - table[i];
        uint64_t bit = (input >> src_pos) & 0x01ULL;
        output = (output << 1) | bit; /* append bit to the right of output */
    }
    return output;
}

/* ─────────────────────── DES Functions  ─────────────────────── */

/* Initial permutation performed on the 64-bit plaintext block */
static uint64_t InitialPerm(uint64_t input) { return permute(input, IP, 64, 64); }

/* Apply PC-1 to the 64-bit key to drop parity bits and return the 56-bit result */
static uint64_t pchoice1(uint64_t key) { return permute(key, PC1_TABLE, 56, 64); }

/* Combine two 28-bit halves (C and D) into 56 bits and apply PC-2 to produce 48-bit subkey */
static uint64_t pchoice2(uint32_t c, uint32_t d)
{
    uint64_t input = ((uint64_t)c << 28) | (uint64_t)d;
    return permute(input, PC2_TABLE, 48, 56);
}

/* Left circular shift for 28-bit halves.
   We mask with 0x0FFFFFFF to keep only 28 bits (drop higher bits). */
static uint32_t leftCircularshift(uint32_t input, int n)
{
    return ((input << n) | (input >> (28 - n))) & 0x0FFFFFFF;
}

/* Apply all eight S-boxes:
   - input: 48-bit value packed into 64-bit
   - we split it into eight groups of 6 bits, use outer bits for row, inner 4 bits for column,
     and then place the 4-bit S-box outputs into the 32-bit result. */
static uint32_t s_box(uint64_t input)
{
    uint32_t output = 0;
    for (int i = 1; i <= 8; i++) {
        /* Extract the 6-bit chunk for the current S-box (from left to right). */
        uint16_t current = (input >> (48 - i * 6)) & 0x3F;
        /* Row is formed by bits b5 and b0 (outer bits), column by middle 4 bits. */
        int y = (current & 0x01) | ((current & 0x20) >> 4);
        int x = (current >> 1) & 0xF;
        /* Place the 4-bit S-box output into the correct position of the 32-bit result. */
        output |= (uint32_t)S_BOX[i - 1][y][x] << (28 - ((i - 1) * 4));
    }
    return output;
}

/* The Feistel F-function:
   Steps:
    1) expand 32-bit input to 48 bits
    2) XOR with the 48-bit subkey
    3) run through S-boxes to get 32 bits
    4) apply P-permutation and return the final 32-bit value
   This value is then XORed with the left half in the main DES round. */
static uint32_t feistel(uint32_t input, uint64_t subkey)
{
    uint64_t exp = permute(input, expansion, 48, 32); /* expand R to 48 bits */
    exp ^= subkey;                                   /* mix with the subkey */
    uint32_t output = s_box(exp);                    /* substitute via S-boxes */
    return permute(output, permutation, 32, 32);     /* final permutation P */
}

/* DES encryption of a single 64-bit block using a 64-bit key.
   Summary of steps:
    - initial permutation on the plaintext
    - generate 16 round subkeys (PC-1, shifts, PC-2)
    - perform 16 Feistel rounds (L,R swaps each round)
    - final inverse IP to get the ciphertext */
static uint64_t DESencryption(uint64_t input, uint64_t key)
{
    uint64_t ip_output = InitialPerm(input); /* step 1: IP */
    uint64_t pc1_output = pchoice1(key);     /* step 2: PC-1 to form C0 and D0 */
    uint32_t c[17], d[17];
    uint64_t subkey[17];

    /* split PC1 result into two 28-bit halves C0 and D0 */
    c[0] = (pc1_output >> 28) & 0x0FFFFFFF;
    d[0] = (pc1_output) & 0x0FFFFFFF;

    /* key schedule: produce 16 subkeys */
    for (int i = 1; i <= 16; i++) {
        c[i] = leftCircularshift(c[i - 1], shifts[i - 1]); /* rotate C */
        d[i] = leftCircularshift(d[i - 1], shifts[i - 1]); /* rotate D */
        subkey[i] = pchoice2(c[i], d[i]);                  /* PC-2 -> Ki */
    }

    /* split permuted plaintext into L0 and R0 */
    uint32_t L = ip_output >> 32;
    uint32_t R = ip_output & 0xFFFFFFFFU;
    /* 16 rounds of DES */
    for (int i = 1; i <= 16; i++) {
        uint32_t temp = R;
        /* R_i = L_{i-1} XOR F(R_{i-1}, K_i) */
        R = L ^ feistel(R, subkey[i]);
        /* L_i = R_{i-1} */
        L = temp;
    }

    /* pre-output is R16 || L16 (note the final swap), then apply inverse IP */
    uint64_t pre_output = ((uint64_t)R << 32) | (uint64_t)L;
    uint64_t output = permute(pre_output, inverse_IP, 64, 64); /* apply IP^-1 */
    return output;
}

/* ─────────────────────── MAIN TEST  ─────────────────────── */

/* Main function: simple test harness that encrypts two example blocks
   and prints the results in hex. ULL suffix ensures 64-bit constants. */
int main(void)
{
    /* Example DES key (includes parity bits) */
    uint64_t key = 0x133457799BBCDFF1ULL;
    /* Example plaintext block */
    uint64_t input = 0x0123456789ABCDEFULL;

    /* Encrypt and print results. These are known test vectors for DES. */
    show_hex(DESencryption(input, key));
    show_hex(DESencryption(0x12475321ABCD1234ULL, key));

    return 0;
}