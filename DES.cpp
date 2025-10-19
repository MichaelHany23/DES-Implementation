#include <iostream>
#include <stdint.h>
#include "Tables.hpp"

using namespace std;
string bin(uint64_t n);
void show_hex(uint64_t num);
uint64_t permute(uint64_t input, const int* table, int nbits_out , int nbits_input);


uint64_t InitialPerm(uint64_t input)
{
    return ( permute(input , IP , 64 , 64) );

}
uint64_t pchoice1(uint64_t key)
{

    return  permute(key, PC1_TABLE, 56 , 64);;

}
uint64_t pchoice2(uint32_t c ,uint32_t d )
{
    uint64_t input = ( (uint64_t)(c) << 28 ) |(uint64_t)(d) ;
    //show_hex(input);
     return permute (input , PC2_TABLE , 48 , 56);
     
}
uint32_t leftCircularshift(uint32_t input   , int n)
{

    return ((input <<n ) | ( input>> (28-n))) & 0x0FFFFFFF ;
}
uint32_t s_box(uint64_t input)
{
    uint16_t current= 0;
    uint32_t output = 0;
    for(int i = 1 ; i <= 8 ; i++)
    {
        current = (input >> (48 - (i)*6 )) & 0x3F ; 
        // there is no Concatenation operator like in verlpg
        int y = (current & 0x01)| ((current & 0x20) >> 4) ;
        int x= (current >> 1) & 0xF;
        output |=  (uint32_t) S_BOX[i-1][y][x] << (28 - ((i-1)*4));
     
    }
    return output;
} 
uint32_t feistel (uint32_t input , uint64_t subkey)
{
    uint64_t c = permute ( input , expansion , 48 , 32 );
    c = c ^ subkey;
    uint32_t output = s_box(c);
    //permutation
    output = permute(output, permutation, 32, 32);

    return output;

}


uint64_t DESencryption(uint64_t input , uint64_t key )
{

    uint64_t ip_output = InitialPerm(input); 
    uint64_t pc1_output = pchoice1(key); 
    uint32_t c[17] , d[17] ;
    uint64_t subkey[17];
    
    //cout << bin(ip_output) << endl;
    //show_hex(ip_output);
    c[0] = (pc1_output >> 28) & 0x0fffffff;
    d[0] = (pc1_output) &0x0fffffff;
    //show_hex(c[0]);
    //show_hex(d[0]);
    for (int i = 1; i <= 16; i++) {
    c[i] = leftCircularshift(c[i-1], shifts[i-1]);
    d[i] = leftCircularshift(d[i-1], shifts[i-1]);
    subkey[i] = pchoice2(c[i], d[i]);
    }
    //show_hex(c[1]);
    //show_hex(d[1]);
    //show_hex(subkey[1]);
    ////

    //DESRound()
    uint32_t left[17],right[17];
    left[0]= ip_output >> 32 ;
    right[0]= ip_output ;
    //show_hex(left[0]);
    //show_hex(right[0]);
    for(int i = 1 ; i <= 16 ; i++)
    {        
        uint64_t r = right[i-1];
        r = (uint32_t)feistel(r, subkey[i]);
        left[i] = right[i-1];
        right[i] = left[i-1] ^ (r);
    }
    // you need to swap left and right
    // the produced is R16 || L16
    uint64_t output = 0;
    output = ((uint64_t) right[16] << 32 ) |(uint64_t) left[16];
    output = permute ( output , inverse_IP , 64 , 64 );

    return output;

}

int main()
{
    uint64_t key   = 0x133457799BBCDFF1; // example DES key
    uint64_t input = 0x0123456789ABCDEF;

    show_hex( DESencryption(input , key));
    show_hex( DESencryption(0x12475321abcd1234 , key) );

 
    /*uint64_t ip_output = IP(input); 
    cout << "IP:  " << bin(ip_output) << endl;
    show_hex(ip_output);
    uint64_t pc1_output = pchoice1(key); 
    cout << "PC1: " << bin(pc1_output) << endl;
    show_hex(pc1_output);*/

    return 0;
}











string bin(uint64_t n) {
    string binary = "";
    for (int i = 63; i >= 0; i--) {
        binary += ((n >> i) & 1ULL) ? '1' : '0';

    }cout << endl;
    return binary;
}

void show_hex(uint64_t num) {
    cout << "0x" << hex << num << endl;
}

uint64_t permute(uint64_t input, const int* table, int nbits_out, int nbits_input)
{
    uint64_t output = 0ULL;

    for (int i = 0; i < nbits_out; i++)
    {
        int src_pos = nbits_input - table[i];        // convert 1-based to 0-based bit index from MSB
        uint64_t bit = (input >> src_pos) & 0x01ULL; // extract bit
        output = (output << 1) | bit;                // build output MSB-first
    }

    return output;
}
