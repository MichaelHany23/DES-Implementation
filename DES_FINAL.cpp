#include <iostream>
#include <stdint.h>

using namespace std;
uint64_t permute(uint64_t input , int* table , int nbits)
{

    uint64_t output = 0x0;
    for(int i = 0 ; i < nbits ;i ++)
    {
        int pos = table[i]-1;
        uint64_t bit = input & (1ULL << (nbits-1-pos));

        int des= nbits-1-i;
        if (nbits - 1 - pos > des)
            bit >>= (nbits - 1 - pos - des);
        else
            bit <<= (des - (nbits - 1 - pos));


        output = output | bit;
    }
    return output;
}
uint64_t IP(uint64_t input)
{
    int tableIP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};
    return ( permute(input , tableIP  , 64) );

}
uint64_t pchoice1(uint64_t key)
{

    int tablePC1[56] = {
    // Left half (C)
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,

    // Right half (D)
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};
    return ( permute(input , tableIP  , 64) );

}
uint64_t DESencryption(uint64_t input , uint64_t key)
{

     uint64_t output =IP(input);
     uint64_t K = pchoice1()


}


int main()
{

    //uint64_t input = 0xF5;
    uint64_t input = 0x0123456789ABCDEF;
    uint64_t output =IP(input);
    cout << bin(input) <<endl;
    cout << bin(output) <<endl;

}
