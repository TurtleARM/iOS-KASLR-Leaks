//
//  decode.h
//  kaslr
//
//  Created by Davide Ornaghi on 8/24/18.
//  Copyright (c) 2018 Davide Ornaghi. All rights reserved.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef kaslr_decode_h
#define kaslr_decode_h

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

void build_decoding_table();

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);
void base64_cleanup();

#endif
