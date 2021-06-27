//
//  Signature.hpp
//  Composant-Signature
//
//  Created by Henri Aycard on 26/06/2021.
//  Copyright © 2021 Aycard. All rights reserved.
//
#pragma once
#ifndef Signature_h
#define Signature_h

#include <stdio.h>
#include <vector>
#include <string>
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace std;

class Signature {
public:
    string signMessage(string data, string private_key);
    bool validateSignature(string data, string public_key, string signature);
private:
    uint8_t* hex_str_to_uint8(const char* string);
};


#endif /* Signature_hpp */
