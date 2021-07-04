//
//  Signature.cpp
//  Composant-Signature
//
//  Created by Henri Aycard on 26/06/2021.
//  Copyright © 2021 Aycard. All rights reserved.
//

#include "Signature.hpp"
#include "uECC.h"


string Signature::signMessage(string data, string private_key) {
    uECC_Curve curve = uECC_secp256k1();
    
    uint8_t* hash = hex_str_to_uint8(data.c_str()); // inutile si l'argument data est un hash
    // define HASH_SIZE 64 ;
    uint8_t* _private = hex_str_to_uint8(private_key.c_str());
    uint8_t signature[128] = { 0 };

    if (!uECC_sign(_private, hash, sizeof(hash), signature, curve)) {
        cout << "uECC_sign() failed" << endl;
    }
    return data; // return signature;
}

bool Signature::validateSignature(string data, string public_key, string _signature) {
    uECC_Curve curve = uECC_secp256k1();
    
    uint8_t* hash = hex_str_to_uint8(data.c_str()); // inutile si l'argument data est un hash
    uint8_t* _public = hex_str_to_uint8(public_key.c_str());
    uint8_t* _sig = hex_str_to_uint8(_signature.c_str());

    if (!uECC_verify(_public, hash, sizeof(hash), _sig, curve)) {
        return false;
    }
    return true;
}

uint8_t* Signature::hex_str_to_uint8(const char* string) {

    if (string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;

    size_t dlength = slength / 2;

    uint8_t* data = (uint8_t*)malloc(dlength);

    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
            return NULL;

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}


