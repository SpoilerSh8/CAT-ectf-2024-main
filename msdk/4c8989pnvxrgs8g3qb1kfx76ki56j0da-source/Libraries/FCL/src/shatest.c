/******************************************************************************* 
* Copyright (C) 2017 Maxim Integrated Products, Inc., All rights Reserved.
* * This software is protected by copyright laws of the United States and
* of foreign countries. This material may also be protected by patent laws
* and technology transfer regulations of the United States and of foreign
* countries. This software is furnished under a license agreement and/or a
* nondisclosure agreement and may only be used or reproduced in accordance
* with the terms of those agreements. Dissemination of this information to
* any party or parties not specified in the license agreement and/or
* nondisclosure agreement is expressly prohibited.
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
* OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
* 
* Except as contained in this notice, the name of Maxim Integrated 
* Products, Inc. shall not be used except as stated in the Maxim Integrated 
* Products, Inc. Branding Policy.
*
* The mere transfer of this software does not imply any licenses
* of trade secrets, proprietary technology, copyrights, patents,
* trademarks, maskwork rights, or any other form of intellectual
* property whatsoever. Maxim Integrated Products, Inc. retains all 
* ownership rights.*/



//#define VERBOSE
#include <ucl_testing_config.h>
#include <ucl/ucl_hash.h>
#include <ucl/ucl_retdefs.h>
#include <ucl/ucl_types.h>
#include <ucl/ucl_config.h>
#include <ucl/ucl_defs.h>
#include <ucl/ucl_sha256.h>
#include <ucl/ucl_sha384.h>
#include <ucl/ucl_sia256.h>
#include <ucl/ucl_sha3.h>
#include "string.h"


//HMAC RFC 4231 test vectors for HMAC SHA-224, SHA-256, SHA-384 and SHA-512
u8 key_rfc4231_1[]={0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
u8 msg_rfc4231_1[]={0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65};
u8 mac224_rfc4231_1[]={0x89,0x6f,0xb1,0x12,0x8a,0xbb,0xdf,0x19,0x68,0x32,0x10,0x7c,0xd4,0x9d,0xf3,0x3f,0x47,0xb4,0xb1,0x16,0x99,0x12,0xba,0x4f,0x53,0x68,0x4b,0x22};
u8 mac256_rfc4231_1[]={0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
u8 mac384_rfc4231_1[]={0xaf,0xd0,0x39,0x44,0xd8,0x48,0x95,0x62,0x6b,0x08,0x25,0xf4,0xab,0x46,0x90,0x7f,0x15,0xf9,0xda,0xdb,0xe4,0x10,0x1e,0xc6,0x82,0xaa,0x03,0x4c,0x7c,0xeb,0xc5,0x9c,0xfa,0xea,0x9e,0xa9,0x07,0x6e,0xde,0x7f,0x4a,0xf1,0x52,0xe8,0xb2,0xfa,0x9c,0xb6};
u8 mac512_rfc4231_1[]={0x87,0xaa,0x7c,0xde,0xa5,0xef,0x61,0x9d,0x4f,0xf0,0xb4,0x24,0x1a,0x1d,0x6c,0xb0,0x23,0x79,0xf4,0xe2,0xce,0x4e,0xc2,0x78,0x7a,0xd0,0xb3,0x05,0x45,0xe1,0x7c,0xde,0xda,0xa8,0x33,0xb7,0xd6,0xb8,0xa7,0x02,0x03,0x8b,0x27,0x4e,0xae,0xa3,0xf4,0xe4,0xbe,0x9d,0x91,0x4e,0xeb,0x61,0xf1,0x70,0x2e,0x69,0x6c,0x20,0x3a,0x12,0x68,0x54};

u8 key_rfc4231_2[]={0x4a,0x65,0x66,0x65};
u8 msg_rfc4231_2[]={0x77,0x68,0x61,0x74,0x20,0x64,0x6f,0x20,0x79,0x61,0x20,0x77,0x61,0x6e,0x74,0x20,0x66,0x6f,0x72,0x20,0x6e,0x6f,0x74,0x68,0x69,0x6e,0x67,0x3f};

u8 mac224_rfc4231_2[]={0xa3,0x0e,0x01,0x09,0x8b,0xc6,0xdb,0xbf,0x45,0x69,0x0f,0x3a,0x7e,0x9e,0x6d,0x0f,0x8b,0xbe,0xa2,0xa3,0x9e,0x61,0x48,0x00,0x8f,0xd0,0x5e,0x44};
u8 mac256_rfc4231_2[]={0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43};
u8 mac384_rfc4231_2[]={0xaf,0x45,0xd2,0xe3,0x76,0x48,0x40,0x31,0x61,0x7f,0x78,0xd2,0xb5,0x8a,0x6b,0x1b,0x9c,0x7e,0xf4,0x64,0xf5,0xa0,0x1b,0x47,0xe4,0x2e,0xc3,0x73,0x63,0x22,0x44,0x5e,0x8e,0x22,0x40,0xca,0x5e,0x69,0xe2,0xc7,0x8b,0x32,0x39,0xec,0xfa,0xb2,0x16,0x49};
u8 mac512_rfc4231_2[]={0x16,0x4b,0x7a,0x7b,0xfc,0xf8,0x19,0xe2,0xe3,0x95,0xfb,0xe7,0x3b,0x56,0xe0,0xa3,0x87,0xbd,0x64,0x22,0x2e,0x83,0x1f,0xd6,0x10,0x27,0x0c,0xd7,0xea,0x25,0x05,0x54,0x97,0x58,0xbf,0x75,0xc0,0x5a,0x99,0x4a,0x6d,0x03,0x4f,0x65,0xf8,0xf0,0xe6,0xfd,0xca,0xea,0xb1,0xa3,0x4d,0x4a,0x6b,0x4b,0x63,0x6e,0x07,0x0a,0x38,0xbc,0xe7,0x37};

u8 key_rfc4231_3[]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
u8 msg_rfc4231_3[]={0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd};

u8 mac224_rfc4231_3[]={0x7f,0xb3,0xcb,0x35,0x88,0xc6,0xc1,0xf6,0xff,0xa9,0x69,0x4d,0x7d,0x6a,0xd2,0x64,0x93,0x65,0xb0,0xc1,0xf6,0x5d,0x69,0xd1,0xec,0x83,0x33,0xea};
u8 mac256_rfc4231_3[]={0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7,0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe};
u8 mac384_rfc4231_3[]={0x88,0x06,0x26,0x08,0xd3,0xe6,0xad,0x8a,0x0a,0xa2,0xac,0xe0,0x14,0xc8,0xa8,0x6f,0x0a,0xa6,0x35,0xd9,0x47,0xac,0x9f,0xeb,0xe8,0x3e,0xf4,0xe5,0x59,0x66,0x14,0x4b,0x2a,0x5a,0xb3,0x9d,0xc1,0x38,0x14,0xb9,0x4e,0x3a,0xb6,0xe1,0x01,0xa3,0x4f,0x27};
u8 mac512_rfc4231_3[]={0xfa,0x73,0xb0,0x08,0x9d,0x56,0xa2,0x84,0xef,0xb0,0xf0,0x75,0x6c,0x89,0x0b,0xe9,0xb1,0xb5,0xdb,0xdd,0x8e,0xe8,0x1a,0x36,0x55,0xf8,0x3e,0x33,0xb2,0x27,0x9d,0x39,0xbf,0x3e,0x84,0x82,0x79,0xa7,0x22,0xc8,0x06,0xb4,0x85,0xa4,0x7e,0x67,0xc8,0x07,0xb9,0x46,0xa3,0x37,0xbe,0xe8,0x94,0x26,0x74,0x27,0x88,0x59,0xe1,0x32,0x92,0xfb};

u8 key_rfc4231_4[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19};
u8 msg_rfc4231_4[]={0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd};

u8 mac224_rfc4231_4[]={0x6c,0x11,0x50,0x68,0x74,0x01,0x3c,0xac,0x6a,0x2a,0xbc,0x1b,0xb3,0x82,0x62,0x7c,0xec,0x6a,0x90,0xd8,0x6e,0xfc,0x01,0x2d,0xe7,0xaf,0xec,0x5a,};
u8 mac256_rfc4231_4[]={0x82,0x55,0x8a,0x38,0x9a,0x44,0x3c,0x0e,0xa4,0xcc,0x81,0x98,0x99,0xf2,0x08,0x3a,0x85,0xf0,0xfa,0xa3,0xe5,0x78,0xf8,0x07,0x7a,0x2e,0x3f,0xf4,0x67,0x29,0x66,0x5b};
u8 mac384_rfc4231_4[]={0x3e,0x8a,0x69,0xb7,0x78,0x3c,0x25,0x85,0x19,0x33,0xab,0x62,0x90,0xaf,0x6c,0xa7,0x7a,0x99,0x81,0x48,0x08,0x50,0x00,0x9c,0xc5,0x57,0x7c,0x6e,0x1f,0x57,0x3b,0x4e,0x68,0x01,0xdd,0x23,0xc4,0xa7,0xd6,0x79,0xcc,0xf8,0xa3,0x86,0xc6,0x74,0xcf,0xfb};
u8 mac512_rfc4231_4[]={0xb0,0xba,0x46,0x56,0x37,0x45,0x8c,0x69,0x90,0xe5,0xa8,0xc5,0xf6,0x1d,0x4a,0xf7,0xe5,0x76,0xd9,0x7f,0xf9,0x4b,0x87,0x2d,0xe7,0x6f,0x80,0x50,0x36,0x1e,0xe3,0xdb,0xa9,0x1c,0xa5,0xc1,0x1a,0xa2,0x5e,0xb4,0xd6,0x79,0x27,0x5c,0xc5,0x78,0x80,0x63,0xa5,0xf1,0x97,0x41,0x12,0x0c,0x4f,0x2d,0xe2,0xad,0xeb,0xeb,0x10,0xa2,0x98,0xdd};

u8 key_rfc4231_6[]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
u8 msg_rfc4231_6[]={0x54,0x65,0x73,0x74,0x20,0x55,0x73,0x69,0x6e,0x67,0x20,0x4c,0x61,0x72,0x67,0x65,0x72,0x20,0x54,0x68,0x61,0x6e,0x20,0x42,0x6c,0x6f,0x63,0x6b,0x2d,0x53,0x69,0x7a,0x65,0x20,0x4b,0x65,0x79,0x20,0x2d,0x20,0x48,0x61,0x73,0x68,0x20,0x4b,0x65,0x79,0x20,0x46,0x69,0x72,0x73,0x74};

u8 mac224_rfc4231_6[]={0x95,0xe9,0xa0,0xdb,0x96,0x20,0x95,0xad,0xae,0xbe,0x9b,0x2d,0x6f,0x0d,0xbc,0xe2,0xd4,0x99,0xf1,0x12,0xf2,0xd2,0xb7,0x27,0x3f,0xa6,0x87,0x0e};
u8 mac256_rfc4231_6[]={0x60,0xe4,0x31,0x59,0x1e,0xe0,0xb6,0x7f,0x0d,0x8a,0x26,0xaa,0xcb,0xf5,0xb7,0x7f,0x8e,0x0b,0xc6,0x21,0x37,0x28,0xc5,0x14,0x05,0x46,0x04,0x0f,0x0e,0xe3,0x7f,0x54};
u8 mac384_rfc4231_6[]={0x4e,0xce,0x08,0x44,0x85,0x81,0x3e,0x90,0x88,0xd2,0xc6,0x3a,0x04,0x1b,0xc5,0xb4,0x4f,0x9e,0xf1,0x01,0x2a,0x2b,0x58,0x8f,0x3c,0xd1,0x1f,0x05,0x03,0x3a,0xc4,0xc6,0x0c,0x2e,0xf6,0xab,0x40,0x30,0xfe,0x82,0x96,0x24,0x8d,0xf1,0x63,0xf4,0x49,0x52};
u8 mac512_rfc4231_6[]={0x80,0xb2,0x42,0x63,0xc7,0xc1,0xa3,0xeb,0xb7,0x14,0x93,0xc1,0xdd,0x7b,0xe8,0xb4,0x9b,0x46,0xd1,0xf4,0x1b,0x4a,0xee,0xc1,0x12,0x1b,0x01,0x37,0x83,0xf8,0xf3,0x52,0x6b,0x56,0xd0,0x37,0xe0,0x5f,0x25,0x98,0xbd,0x0f,0xd2,0x21,0x5d,0x6a,0x1e,0x52,0x95,0xe6,0x4f,0x73,0xf6,0x3f,0x0a,0xec,0x8b,0x91,0x5a,0x98,0x5d,0x78,0x65,0x98,};


const u8 key_rfc4231_7[]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
const  u8 msg_rfc4231_7[]={0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x61,0x20,0x74,0x65,0x73,0x74,0x20,0x75,0x73,0x69,0x6e,0x67,0x20,0x61,0x20,0x6c,0x61,0x72,0x67,0x65,0x72,0x20,0x74,0x68,0x61,0x6e,0x20,0x62,0x6c,0x6f,0x63,0x6b,0x2d,0x73,0x69,0x7a,0x65,0x20,0x6b,0x65,0x79,0x20,0x61,0x6e,0x64,0x20,0x61,0x20,0x6c,0x61,0x72,0x67,0x65,0x72,0x20,0x74,0x68,0x61,0x6e,0x20,0x62,0x6c,0x6f,0x63,0x6b,0x2d,0x73,0x69,0x7a,0x65,0x20,0x64,0x61,0x74,0x61,0x2e,0x20,0x54,0x68,0x65,0x20,0x6b,0x65,0x79,0x20,0x6e,0x65,0x65,0x64,0x73,0x20,0x74,0x6f,0x20,0x62,0x65,0x20,0x68,0x61,0x73,0x68,0x65,0x64,0x20,0x62,0x65,0x66,0x6f,0x72,0x65,0x20,0x62,0x65,0x69,0x6e,0x67,0x20,0x75,0x73,0x65,0x64,0x20,0x62,0x79,0x20,0x74,0x68,0x65,0x20,0x48,0x4d,0x41,0x43,0x20,0x61,0x6c,0x67,0x6f,0x72,0x69,0x74,0x68,0x6d,0x2e};

const u8 mac224_rfc4231_7[]={0x3a,0x85,0x41,0x66,0xac,0x5d,0x9f,0x02,0x3f,0x54,0xd5,0x17,0xd0,0xb3,0x9d,0xbd,0x94,0x67,0x70,0xdb,0x9c,0x2b,0x95,0xc9,0xf6,0xf5,0x65,0xd1};
u8 mac256_rfc4231_7[]={0x9b,0x09,0xff,0xa7,0x1b,0x94,0x2f,0xcb,0x27,0x63,0x5f,0xbc,0xd5,0xb0,0xe9,0x44,0xbf,0xdc,0x63,0x64,0x4f,0x07,0x13,0x93,0x8a,0x7f,0x51,0x53,0x5c,0x3a,0x35,0xe2};
const u8 mac384_rfc4231_7[]={0x66,0x17,0x17,0x8e,0x94,0x1f,0x02,0x0d,0x35,0x1e,0x2f,0x25,0x4e,0x8f,0xd3,0x2c,0x60,0x24,0x20,0xfe,0xb0,0xb8,0xfb,0x9a,0xdc,0xce,0xbb,0x82,0x46,0x1e,0x99,0xc5,0xa6,0x78,0xcc,0x31,0xe7,0x99,0x17,0x6d,0x38,0x60,0xe6,0x11,0x0c,0x46,0x52,0x3e};
const u8 mac512_rfc4231_7[]={0xe3,0x7b,0x6a,0x77,0x5d,0xc8,0x7d,0xba,0xa4,0xdf,0xa9,0xf9,0x6e,0x5e,0x3f,0xfd,0xde,0xbd,0x71,0xf8,0x86,0x72,0x89,0x86,0x5d,0xf5,0xa3,0x2d,0x20,0xcd,0xc9,0x44,0xb6,0x02,0x2c,0xac,0x3c,0x49,0x82,0xb1,0x0d,0x5e,0xeb,0x55,0xc3,0xe4,0xde,0x15,0x13,0x46,0x76,0xfb,0x6d,0xe0,0x44,0x60,0x65,0xc9,0x74,0x40,0xfa,0x8c,0x6a,0x58};

int hex(char c1,char c2)
{
  int value;
  value=0;
  if(c1>='A' && c1<='F')
    value=(c1-'A'+10);
  if(c1>='a' && c1<='f')
    value=(c1-'a'+10);
  if(c1>='0' && c1<='9')
    value=(c1-'0');
  value*=16;
  if(c2>='A' && c2<='F')
    value+=(c2-'A'+10);
  if(c2>='a' && c2<='f')
    value+=(c2-'a'+10);
  if(c2>='0' && c2<='9')
    value+=(c2-'0');
  return(value);
}

int check(u8 *h,char *sth,int l)
{
  int i;
  //max size of a hash digest
  u8 th[64];
  if((int)strlen(sth)!=l*2)
    {
      PRINTF("ERROR: incorrect string length (%d -> %d\n",(int)strlen(sth),l);
      return(UCL_ERROR);
    }
  for(i=0;i<l;i++)
    th[i]=hex(sth[i*2],sth[i*2+1]);
  if(memcmp(h,th,l)==0)
    {
#ifdef VERBOSE
    PRINTF("OK\n");
#endif
    }
  else
    return(UCL_ERROR);
  return(UCL_OK);
}

int test_sia256(void)
{
  u8 sha256data1[]={0x05,0xC0,0x57,0x52,0x78,0xDA,0x49,0x02,0x2B,0x6E,0x3D,0x40,0x4F,0x8F,0xBD,0xAE,0x3D,0x41,0x55,0x2E,0x27,0x56,0xAF,0xBB,0x99,0x29,0x0A,0x1C,0xDF,0xFB,0xDD,0xE9,0x42,0xFE,0x32,0x56,0xD3,0xD6,0x7F,0xDA,0x1D,0xA0,0x4E,0xCA,0xBE,0x5E,0xFD,0xD5,0xCF,0xAF,0x7D,0xBA,0xA2,0x16,0x68,0x34,0xF8,0xE8,0x99,0x01,0x62,0x8F,0x41,0x1F,0x00,0x1E,0x22,0x40,0xC1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  //expected result
  u8 sha256res1[32]={0xd5,0x3c,0x1d,0xf1,0xff,0x81,0x96,0x36,0x06,0x05,0xb9,0xf1,0x7e,0xf1,0xee,0xf0,0x1b,0xbc,0xea,0x54,0x21,0xc5,0x5f,0xd9,0x56,0x1c,0x7b,0xe3,0xa4,0xa6,0xc8,0xc0};
  u8 digest[UCL_SIA256_HASHSIZE];
  ucl_sia256(digest,sha256data1,sizeof(sha256data1));
  if(memcmp(sha256res1,digest,UCL_SIA256_HASHSIZE)!=0)
    {
      return(UCL_ERROR);
    }
  return(UCL_OK);
}

int test_sha256(void)
{
  // FIPS 180-2
  // "abc" l=24
  u8 sha256data1[]={0x61,0x62,0x63};
  u8 sha256res1[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" l=448b
  u8 sha256data2[]={0x61,0x62,0x63,0x64,0x62,0x63,0x64,0x65,0x63,0x64,0x65,0x66,0x64,0x65,0x66,0x67,0x65,0x66,0x67,0x68,0x66,0x67,0x68,0x69,0x67,0x68,0x69,0x6A,0x68,0x69,0x6A,0x6B,0x69,0x6A,0x6B,0x6C,0x6A,0x6B,0x6C,0x6D,0x6B,0x6C,0x6D,0x6E,0x6C,0x6D,0x6E,0x6F,0x6D,0x6E,0x6F,0x70,0x6E,0x6F,0x70,0x71};
  u8 sha256res2[32]={0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1};

  //data=1 million "a" 1 million 61
  u8 sha256res3[]={0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0};
  int i;
  u8 million[1000];
  ucl_sha256_ctx_t ctxt;
  int err;
  u8 digest[UCL_SHA256_HASHSIZE];
  err=ucl_sha256(digest,sha256data1,sizeof(sha256data1));
  if(err!=UCL_OK)
    return(UCL_ERROR);
  if(memcmp(digest,sha256res1,UCL_SHA256_HASHSIZE)!=0)
    return(UCL_ERROR);
  err=ucl_sha256(digest,sha256data2,sizeof(sha256data2));
  if(err!=UCL_OK)
    return(UCL_ERROR);
  if(memcmp(digest,sha256res2,UCL_SHA256_HASHSIZE)!=0)
    return(UCL_ERROR);
  for(i=0;i<(int)sizeof(million);i++)
    million[i]='a';

  ucl_sha256_init(&ctxt);
  for(i=0;i<1000000/(int)sizeof(million);i++)
    ucl_sha256_core(&ctxt,million,sizeof(million));
  ucl_sha256_finish(digest,&ctxt);
  if(memcmp(digest,sha256res3,UCL_SHA256_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha256(digest,million,128);
  return(UCL_OK);
}

int test_sha3(void)
{
  u8 abc[]={0x61,0x62,0x63};
  u8 sha3_abc_224[]={0xe6,0x42,0x82,0x4c,0x3f,0x8c,0xf2,0x4a,0xd0,0x92,0x34,0xee,0x7d,0x3c,0x76,0x6f,0xc9,0xa3,0xa5,0x16,0x8d,0x0c,0x94,0xad,0x73,0xb4,0x6f,0xdf};
  u8 sha3_abc_256[]={0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32};
  u8 sha3_abc_384[]={0xec,0x01,0x49,0x82,0x88,0x51,0x6f,0xc9,0x26,0x45,0x9f,0x58,0xe2,0xc6,0xad,0x8d,0xf9,0xb4,0x73,0xcb,0x0f,0xc0,0x8c,0x25,0x96,0xda,0x7c,0xf0,0xe4,0x9b,0xe4,0xb2,0x98,0xd8,0x8c,0xea,0x92,0x7a,0xc7,0xf5,0x39,0xf1,0xed,0xf2,0x28,0x37,0x6d,0x25};
  u8 sha3_abc_512[]={0xb7,0x51,0x85,0x0b,0x1a,0x57,0x16,0x8a,0x56,0x93,0xcd,0x92,0x4b,0x6b,0x09,0x6e,0x08,0xf6,0x21,0x82,0x74,0x44,0xf7,0x0d,0x88,0x4f,0x5d,0x02,0x40,0xd2,0x71,0x2e,0x10,0xe1,0x16,0xe9,0x19,0x2a,0xf3,0xc9,0x1a,0x7e,0xc5,0x76,0x47,0xe3,0x93,0x40,0x57,0x34,0x0b,0x4c,0xf4,0x08,0xd5,0xa5,0x65,0x92,0xf8,0x27,0x4e,0xec,0x53,0xf0};
  // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" l=448b
  u8 abcopq[]={0x61,0x62,0x63,0x64,0x62,0x63,0x64,0x65,0x63,0x64,0x65,0x66,0x64,0x65,0x66,0x67,0x65,0x66,0x67,0x68,0x66,0x67,0x68,0x69,0x67,0x68,0x69,0x6A,0x68,0x69,0x6A,0x6B,0x69,0x6A,0x6B,0x6C,0x6A,0x6B,0x6C,0x6D,0x6B,0x6C,0x6D,0x6E,0x6C,0x6D,0x6E,0x6F,0x6D,0x6E,0x6F,0x70,0x6E,0x6F,0x70,0x71};
  u8 sha3_abcopq_224[]={0x8a,0x24,0x10,0x8b,0x15,0x4a,0xda,0x21,0xc9,0xfd,0x55,0x74,0x49,0x44,0x79,0xba,0x5c,0x7e,0x7a,0xb7,0x6e,0xf2,0x64,0xea,0xd0,0xfc,0xce,0x33};
  u8 sha3_void_224[]={0x6b,0x4e,0x03,0x42,0x36,0x67,0xdb,0xb7,0x3b,0x6e,0x15,0x45,0x4f,0x0e,0xb1,0xab,0xd4,0x59,0x7f,0x9a,0x1b,0x07,0x8e,0x3f,0x5b,0x5a,0x6b,0xc7};
  u8 sha3_abcopq_256[]={0x41,0xc0,0xdb,0xa2,0xa9,0xd6,0x24,0x08,0x49,0x10,0x03,0x76,0xa8,0x23,0x5e,0x2c,0x82,0xe1,0xb9,0x99,0x8a,0x99,0x9e,0x21,0xdb,0x32,0xdd,0x97,0x49,0x6d,0x33,0x76};
  u8 sha3_void_256[]={0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a};
  u8 sha3_abcopq_384[]={0x99,0x1c,0x66,0x57,0x55,0xeb,0x3a,0x4b,0x6b,0xbd,0xfb,0x75,0xc7,0x8a,0x49,0x2e,0x8c,0x56,0xa2,0x2c,0x5c,0x4d,0x7e,0x42,0x9b,0xfd,0xbc,0x32,0xb9,0xd4,0xad,0x5a,0xa0,0x4a,0x1f,0x07,0x6e,0x62,0xfe,0xa1,0x9e,0xef,0x51,0xac,0xd0,0x65,0x7c,0x22};
  u8 sha3_void_384[]={0x0c,0x63,0xa7,0x5b,0x84,0x5e,0x4f,0x7d,0x01,0x10,0x7d,0x85,0x2e,0x4c,0x24,0x85,0xc5,0x1a,0x50,0xaa,0xaa,0x94,0xfc,0x61,0x99,0x5e,0x71,0xbb,0xee,0x98,0x3a,0x2a,0xc3,0x71,0x38,0x31,0x26,0x4a,0xdb,0x47,0xfb,0x6b,0xd1,0xe0,0x58,0xd5,0xf0,0x04};
  u8 sha3_abcopq_512[]={0x04,0xa3,0x71,0xe8,0x4e,0xcf,0xb5,0xb8,0xb7,0x7c,0xb4,0x86,0x10,0xfc,0xa8,0x18,0x2d,0xd4,0x57,0xce,0x6f,0x32,0x6a,0x0f,0xd3,0xd7,0xec,0x2f,0x1e,0x91,0x63,0x6d,0xee,0x69,0x1f,0xbe,0x0c,0x98,0x53,0x02,0xba,0x1b,0x0d,0x8d,0xc7,0x8c,0x08,0x63,0x46,0xb5,0x33,0xb4,0x9c,0x03,0x0d,0x99,0xa2,0x7d,0xaf,0x11,0x39,0xd6,0xe7,0x5e};
  u8 sha3_void_512[]={0xa6,0x9f,0x73,0xcc,0xa2,0x3a,0x9a,0xc5,0xc8,0xb5,0x67,0xdc,0x18,0x5a,0x75,0x6e,0x97,0xc9,0x82,0x16,0x4f,0xe2,0x58,0x59,0xe0,0xd1,0xdc,0xc1,0x47,0x5c,0x80,0xa6,0x15,0xb2,0x12,0x3a,0xf1,0xf5,0xf9,0x4c,0x11,0xe3,0xe9,0x40,0x2c,0x3a,0xc5,0x58,0xf5,0x00,0x19,0x9d,0x95,0xb6,0xd3,0xe3,0x01,0x75,0x85,0x86,0x28,0x1d,0xcd,0x26};
  //data=1 million "a" 1 million 61
  u8 sha3_million_a_224[]={0xd6,0x93,0x35,0xb9,0x33,0x25,0x19,0x2e,0x51,0x6a,0x91,0x2e,0x6d,0x19,0xa1,0x5c,0xb5,0x1c,0x6e,0xd5,0xc1,0x52,0x43,0xe7,0xa7,0xfd,0x65,0x3c};
  u8 sha3_million_a_256[]={0x5c,0x88,0x75,0xae,0x47,0x4a,0x36,0x34,0xba,0x4f,0xd5,0x5e,0xc8,0x5b,0xff,0xd6,0x61,0xf3,0x2a,0xca,0x75,0xc6,0xd6,0x99,0xd0,0xcd,0xcb,0x6c,0x11,0x58,0x91,0xc1};
  u8 sha3_million_a_384[]={0xee,0xe9,0xe2,0x4d,0x78,0xc1,0x85,0x53,0x37,0x98,0x34,0x51,0xdf,0x97,0xc8,0xad,0x9e,0xed,0xf2,0x56,0xc6,0x33,0x4f,0x8e,0x94,0x8d,0x25,0x2d,0x5e,0x0e,0x76,0x84,0x7a,0xa0,0x77,0x4d,0xdb,0x90,0xa8,0x42,0x19,0x0d,0x2c,0x55,0x8b,0x4b,0x83,0x40};
  u8 sha3_million_a_512[]={0x3c,0x3a,0x87,0x6d,0xa1,0x40,0x34,0xab,0x60,0x62,0x7c,0x07,0x7b,0xb9,0x8f,0x7e,0x12,0x0a,0x2a,0x53,0x70,0x21,0x2d,0xff,0xb3,0x38,0x5a,0x18,0xd4,0xf3,0x88,0x59,0xed,0x31,0x1d,0x0a,0x9d,0x51,0x41,0xce,0x9c,0xc5,0xc6,0x6e,0xe6,0x89,0xb2,0x66,0xa8,0xaa,0x18,0xac,0xe8,0x28,0x2a,0x0e,0x0d,0xb5,0x96,0xc9,0x0b,0x0a,0x7b,0x87};

  int i;
  u8 digest[UCL_SHA3_512_HASHSIZE];
  u8 million[1000];
  ucl_sha3_ctx_t ctx;
  int err;

  for(i=0;i<1000;i++)
    million[i]='a';

  ucl_sha3_224_init(&ctx);
  err=ucl_sha3_core(&ctx,abc,3);
  if(UCL_OK!=err)
    return(UCL_ERROR);
  err=ucl_sha3_finish(digest,&ctx);
  if(UCL_OK!=err)
    return(UCL_ERROR);
  ucl_sha3_224(digest,abc,sizeof(abc));
  if(memcmp(digest,sha3_abc_224,UCL_SHA3_224_HASHSIZE)!=0)
      return(UCL_ERROR);
  ucl_sha3_224(digest,abcopq,sizeof(abcopq));
  if(memcmp(digest,sha3_abcopq_224,UCL_SHA3_224_HASHSIZE)!=0)
      return(UCL_ERROR);
  ucl_sha3_224(digest,abc,0);
  if(memcmp(digest,sha3_void_224,UCL_SHA3_224_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_224_init(&ctx);
  for(i=0;i<1000;i++)
    ucl_sha3_core(&ctx,million,1000);
  ucl_sha3_finish(digest,&ctx);
  if(memcmp(digest,sha3_million_a_224,UCL_SHA3_224_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_256(digest,abc,sizeof(abc));
  if(memcmp(digest,sha3_abc_256,UCL_SHA3_256_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_256(digest,abcopq,sizeof(abcopq));
  if(memcmp(digest,sha3_abcopq_256,UCL_SHA3_256_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_256(digest,abc,0);
  if(memcmp(digest,sha3_void_256,UCL_SHA3_256_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_256_init(&ctx);
  for(i=0;i<1000;i++)
    ucl_sha3_core(&ctx,million,1000);
  ucl_sha3_finish(digest,&ctx);
  if(memcmp(digest,sha3_million_a_256,UCL_SHA3_256_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_384(digest,abc,sizeof(abc));
  if(memcmp(digest,sha3_abc_384,UCL_SHA3_384_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_384(digest,abcopq,sizeof(abcopq));
  if(memcmp(digest,sha3_abcopq_384,UCL_SHA3_384_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_384(digest,abc,0);
  if(memcmp(digest,sha3_void_384,UCL_SHA3_384_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_384_init(&ctx);
  for(i=0;i<1000;i++)
    ucl_sha3_core(&ctx,million,1000);
  ucl_sha3_finish(digest,&ctx);
  if(memcmp(digest,sha3_million_a_384,UCL_SHA3_384_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_512(digest,abc,sizeof(abc));
  if(memcmp(digest,sha3_abc_512,UCL_SHA3_512_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_512(digest,abcopq,sizeof(abcopq));
  if(memcmp(digest,sha3_abcopq_512,UCL_SHA3_512_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_512(digest,abc,0);
  if(memcmp(digest,sha3_void_512,UCL_SHA3_512_HASHSIZE)!=0)
    return(UCL_ERROR);
  ucl_sha3_512_init(&ctx);
  for(i=0;i<1000;i++)
    ucl_sha3_core(&ctx,million,1000);
  ucl_sha3_finish(digest,&ctx);
  if(memcmp(digest,sha3_million_a_512,UCL_SHA3_512_HASHSIZE)!=0)
    return(UCL_ERROR);
  return(UCL_OK);
}

int test_sha384(void)
{
  /*
SHA-384 Test Data
#1) 0 byte (null message)
38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da
274edebfe76f65fb d51ad2f14898b95b
#2) 111 bytes of zeros
435770712c611be7 293a66dd0dc8d145 0dc7ff7337bfe115 bf058ef2eb9bed09
cee85c26963a5bcc 0905dc2df7cc6a76
#3) 112 bytes of zeros
3e0cbf3aee0e3aa7 0415beae1bd12dd7 db821efa446440f1 2132edffce76f635
e53526a111491e75 ee8e27b9700eec20
#4) 113 bytes of zeros
6be9af2cf3cd5dd1 2c8d9399ec2b34e6 6034fbd699d4e022 1d39074172a38065
6089caafe8f39963 f94cc7c0a07e3d21
#5) 122 bytes of zeros
12a72ae4972776b0 db7d73d160a15ef0 d19645ec96c7f816 411ab780c794aa49
6a22909d941fe671 ed3f3caee900bdd5
#6) 1000 bytes of zeros
aae017d4ae5b6346 dd60a19d52130fb5 5194b6327dd40b89 c11efc8222292de8
1e1a23c9b59f9f58 b7f6ad463fa108ca
#7) 1000 bytes of 0x41 'A'
7df01148677b7f18 617eee3a23104f0e ed6bb8c90a6046f7 15c9445ff43c30d6
9e9e7082de39c345 2fd1d3afd9ba0689
#8) 1005 bytes of 0x55 'U'
1bb8e256da4a0d1e 87453528254f223b 4cb7e49c4420dbfa 766bba4adba44eec
a392ff6a9f565bc3 47158cc970ce44ec
#9) 1000000 bytes of zeros
8a1979f9049b3fff 15ea3a43a4cf84c6 34fd14acad1c333f ecb72c588b68868b
66a994386dc0cd16 87b9ee2e34983b81
#10) 0x20000000 (536870912) bytes of 0x5a 'Z'
18aded227cc6b562 cc7fb259e8f40454 9e52914531aa1c5d 85167897c779cc4b
25d0425fd1590e40 bd763ec3f4311c1a
#11) 0x41000000 (1090519040) bytes of zeros
83ab05ca483abe3f aa597ad524d31291 ae827c5be2b3efcb 6391bfed31ccd937
b6135e0378c6c7f5 98857a7c516f207a
#12) 0x6000003e (1610612798) bytes of 0x42 'B'
cf852304f8d80209 351b37ce69ca7dcf 34972b4edb781702 8ec55ab67ad3bc96
eecb8241734258a8 5d2afce65d4571e2
  */
  int i;
  ucl_sha384_ctx_t ctx;
  u8 e[UCL_SHA384_HASHSIZE];
  u8 tab[1005];
  u8 digest_void[]={0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b};
  u8 digest_1110[]={0x43,0x57,0x70,0x71,0x2c,0x61,0x1b,0xe7,0x29,0x3a,0x66,0xdd,0x0d,0xc8,0xd1,0x45,0x0d,0xc7,0xff,0x73,0x37,0xbf,0xe1,0x15,0xbf,0x05,0x8e,0xf2,0xeb,0x9b,0xed,0x09,0xce,0xe8,0x5c,0x26,0x96,0x3a,0x5b,0xcc,0x09,0x05,0xdc,0x2d,0xf7,0xcc,0x6a,0x76};
  u8 digest_1120[]={0x3e,0x0c,0xbf,0x3a,0xee,0x0e,0x3a,0xa7,0x04,0x15,0xbe,0xae,0x1b,0xd1,0x2d,0xd7,0xdb,0x82,0x1e,0xfa,0x44,0x64,0x40,0xf1,0x21,0x32,0xed,0xff,0xce,0x76,0xf6,0x35,0xe5,0x35,0x26,0xa1,0x11,0x49,0x1e,0x75,0xee,0x8e,0x27,0xb9,0x70,0x0e,0xec,0x20};
  u8 digest_1130[]={0x6b,0xe9,0xaf,0x2c,0xf3,0xcd,0x5d,0xd1,0x2c,0x8d,0x93,0x99,0xec,0x2b,0x34,0xe6,0x60,0x34,0xfb,0xd6,0x99,0xd4,0xe0,0x22,0x1d,0x39,0x07,0x41,0x72,0xa3,0x80,0x65,0x60,0x89,0xca,0xaf,0xe8,0xf3,0x99,0x63,0xf9,0x4c,0xc7,0xc0,0xa0,0x7e,0x3d,0x21};
  u8 digest_1220[]={0x12,0xa7,0x2a,0xe4,0x97,0x27,0x76,0xb0,0xdb,0x7d,0x73,0xd1,0x60,0xa1,0x5e,0xf0,0xd1,0x96,0x45,0xec,0x96,0xc7,0xf8,0x16,0x41,0x1a,0xb7,0x80,0xc7,0x94,0xaa,0x49,0x6a,0x22,0x90,0x9d,0x94,0x1f,0xe6,0x71,0xed,0x3f,0x3c,0xae,0xe9,0x00,0xbd,0xd5};
  u8 digest_10000[]={0xaa,0xe0,0x17,0xd4,0xae,0x5b,0x63,0x46,0xdd,0x60,0xa1,0x9d,0x52,0x13,0x0f,0xb5,0x51,0x94,0xb6,0x32,0x7d,0xd4,0x0b,0x89,0xc1,0x1e,0xfc,0x82,0x22,0x29,0x2d,0xe8,0x1e,0x1a,0x23,0xc9,0xb5,0x9f,0x9f,0x58,0xb7,0xf6,0xad,0x46,0x3f,0xa1,0x08,0xca};
  u8 digest_1000A[]={0x7d,0xf0,0x11,0x48,0x67,0x7b,0x7f,0x18,0x61,0x7e,0xee,0x3a,0x23,0x10,0x4f,0x0e,0xed,0x6b,0xb8,0xc9,0x0a,0x60,0x46,0xf7,0x15,0xc9,0x44,0x5f,0xf4,0x3c,0x30,0xd6,0x9e,0x9e,0x70,0x82,0xde,0x39,0xc3,0x45,0x2f,0xd1,0xd3,0xaf,0xd9,0xba,0x06,0x89};
  u8 digest_1005U[]={0x1b,0xb8,0xe2,0x56,0xda,0x4a,0x0d,0x1e,0x87,0x45,0x35,0x28,0x25,0x4f,0x22,0x3b,0x4c,0xb7,0xe4,0x9c,0x44,0x20,0xdb,0xfa,0x76,0x6b,0xba,0x4a,0xdb,0xa4,0x4e,0xec,0xa3,0x92,0xff,0x6a,0x9f,0x56,0x5b,0xc3,0x47,0x15,0x8c,0xc9,0x70,0xce,0x44,0xec};
  u8 digest_1mil0[]={0x8a,0x19,0x79,0xf9,0x04,0x9b,0x3f,0xff,0x15,0xea,0x3a,0x43,0xa4,0xcf,0x84,0xc6,0x34,0xfd,0x14,0xac,0xad,0x1c,0x33,0x3f,0xec,0xb7,0x2c,0x58,0x8b,0x68,0x86,0x8b,0x66,0xa9,0x94,0x38,0x6d,0xc0,0xcd,0x16,0x87,0xb9,0xee,0x2e,0x34,0x98,0x3b,0x81};
  u8 digest_536Z[]={0x18,0xad,0xed,0x22,0x7c,0xc6,0xb5,0x62,0xcc,0x7f,0xb2,0x59,0xe8,0xf4,0x04,0x54,0x9e,0x52,0x91,0x45,0x31,0xaa,0x1c,0x5d,0x85,0x16,0x78,0x97,0xc7,0x79,0xcc,0x4b,0x25,0xd0,0x42,0x5f,0xd1,0x59,0x0e,0x40,0xbd,0x76,0x3e,0xc3,0xf4,0x31,0x1c,0x1a};
  u8 digest_1090[]={0x83,0xab,0x05,0xca,0x48,0x3a,0xbe,0x3f,0xaa,0x59,0x7a,0xd5,0x24,0xd3,0x12,0x91,0xae,0x82,0x7c,0x5b,0xe2,0xb3,0xef,0xcb,0x63,0x91,0xbf,0xed,0x31,0xcc,0xd9,0x37,0xb6,0x13,0x5e,0x03,0x78,0xc6,0xc7,0xf5,0x98,0x85,0x7a,0x7c,0x51,0x6f,0x20,0x7a};
#ifdef VERBOSE
  PRINTF("TEST SHA384\n");
  PRINTF("sha384(void)\n");
#endif
  ucl_sha384(e,tab,0);
  //#1) 0 byte (null message)
  if(memcmp(e,digest_void,48)!=0)
    {
      return(UCL_ERROR);
    }

  for(i=0;i<1000;i++)
    tab[i]=0;
  ucl_sha384(e,tab,111);
#ifdef VERBOSE
  PRINTF("sha384(111-0)\n");
#endif
  //#2) 111 bytes of zeros
  if(memcmp(e,digest_1110,48)!=0)
    {
      for(i=0;i<48;i++)
	printf("%02x",e[i]);
      printf("\n");
      return(UCL_ERROR);
    }

  ucl_sha384(e,tab,112);
#ifdef VERBOSE
  PRINTF("sha384(112-0)\n");
#endif
  //#3) 112 bytes of zeros
  if(memcmp(e,digest_1120,48)!=0)
    return(UCL_ERROR);

  ucl_sha384(e,tab,113);
#ifdef VERBOSE
  PRINTF("sha384(113-0):");
#endif
  //#4) 113 bytes of zeros
  if(memcmp(e,digest_1130,48)!=0)
    return(UCL_ERROR);

  ucl_sha384(e,tab,122);
#ifdef VERBOSE
  PRINTF("sha384(122-0):");
#endif
  //#5) 122 bytes of zeros
  if(memcmp(e,digest_1220,48)!=0)
    return(UCL_ERROR);
  
  ucl_sha384(e,tab,1000);
#ifdef VERBOSE
  PRINTF("sha384(1000-0):");
#endif
  //#6) 1000 bytes of zeros
  if(memcmp(e,digest_10000,48)!=0)
    return(UCL_ERROR);
  
  for(i=0;i<1000;i++)
    tab[i]='A';
  ucl_sha384(e,tab,1000);
#ifdef VERBOSE
  PRINTF("sha384(1000-A):");
#endif
  //#7) 1000 bytes of 0x41 'A'
  if(memcmp(e,digest_1000A,48)!=0)
    return(UCL_ERROR);

  for(i=0;i<1005;i++)
    tab[i]='U';
  ucl_sha384(e,tab,1005);
#ifdef VERBOSE
  PRINTF("sha384(1005-U):");
#endif
  //#8) 1005 bytes of 0x55 'U'
  if(memcmp(e,digest_1005U,48)!=0)
    return(UCL_ERROR);

  for(i=0;i<1000;i++)
    tab[i]=0;
  ucl_sha384_init(&ctx);
  for(i=0;i<1000;i++)
    ucl_sha384_core(&ctx,tab,1000);
  ucl_sha384_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha384(1mil-0):");
#endif
  //#9) 1000000 bytes of zeros
  if(memcmp(e,digest_1mil0,48)!=0)
    return(UCL_ERROR);

  for(i=0;i<512;i++)
    tab[i]='Z';
  ucl_sha384_init(&ctx);
  for(i=0;i<1048576;i++)
    ucl_sha384_core(&ctx,tab,512);
  ucl_sha384_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha384(2^29-Z):");
#endif
  //#10) 0x20000000 (536870912) bytes of 0x5a 'Z'
  if(memcmp(e,digest_536Z,48)!=0)
    return(UCL_ERROR);

  for(i=0;i<520;i++)
    tab[i]=0;
  ucl_sha384_init(&ctx);
  for(i=0;i<2097152;i++)
    ucl_sha384_core(&ctx,tab,520);
  ucl_sha384_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha384(2^24*5*13-0):");
#endif
  //#11) 0x41000000 (1090519040) bytes of zeros
  if(memcmp(e,digest_1090,48)!=0)
    return(UCL_ERROR);

  return(UCL_OK);
}
int test_sha512(void)
{
  /*
SHA-512 Test Data
#1) 0 byte (null message)
cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce
47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e

#2) 111 bytes of zeros

77ddd3a542e530fd 047b8977c657ba6c e72f1492e360b2b2 212cd264e75ec038
82e4ff0525517ab4 207d14c70c2259ba 88d4d335ee0e7e20 543d22102ab1788c
#3) 112 bytes of zeros
2be2e788c8a8adea a9c89a7f78904cac ea6e39297d75e057 3a73c756234534d6
627ab4156b48a665 7b29ab8beb733340 40ad39ead81446bb 09c70704ec707952
#4) 113 bytes of zeros
0e67910bcf0f9ccd e5464c63b9c850a1 2a759227d16b040d 98986d54253f9f34
322318e56b8feb86 c5fb2270ed87f312 52f7f68493ee7597 43909bd75e4bb544
#5) 122 bytes of zeros
4f3f095d015be4a7 a7cc0b8c04da4aa0 9e74351e3a97651f 744c23716ebd9b3e
822e5077a01baa5c c0ed45b9249e88ab 343d4333539df21e d229da6f4a514e0f
#6) 1000 bytes of zeros
ca3dff61bb23477a a6087b27508264a6 f9126ee3a004f53c b8db942ed345f2f2
d229b4b59c859220 a1cf1913f34248e3 803bab650e849a3d 9a709edc09ae4a76
#7) 1000 bytes of 0x41 �A�
329c52ac62d1fe73 1151f2b895a00475 445ef74f50b979c6 f7bb7cae349328c1
d4cb4f7261a0ab43 f936a24b000651d4 a824fcdd577f211a ef8f806b16afe8af
#8) 1005 bytes of 0x55 �U�
59f5e54fe299c6a8 764c6b199e44924a 37f59e2b56c3ebad 939b7289210dc8e4
c21b9720165b0f4d 4374c90f1bf4fb4a 5ace17a116179801 5052893a48c3d161
#9) 1000000 bytes of zeros
ce044bc9fd43269d 5bbc946cbebc3bb7 11341115cc4abdf2 edbc3ff2c57ad4b1
5deb699bda257fea 5aef9c6e55fcf4cf 9dc25a8c3ce25f2e fe90908379bff7ed
#10) 0x20000000 (536870912) bytes of 0x5a �Z�
da172279f3ebbda9 5f6b6e1e5f0ebec6 82c25d3d93561a16 24c2fa9009d64c7e
9923f3b46bcaf11d 39a531f43297992b a4155c7e827bd0f1 e194ae7ed6de4cac
#11) 0x41000000 (1090519040) bytes of zeros
14b1be901cb43549 b4d831e61e5f9df1 c791c85b50e85f9d 6bc64135804ad43c
e8402750edbe4e5c 0fc170b99cf78b9f 4ecb9c7e02a15791 1d1bd1832d76784f
#12) 0x6000003e (1610612798) bytes of 0x42 �B�
fd05e13eb771f051 90bd97d62647157e a8f1f6949a52bb6d aaedbad5f578ec59
b1b8d6c4a7ecb2fe ca6892b4dc138771 670a0f3bd577eea3 26aed40ab7dd58b1
  */
  int i;
  ucl_sha512_ctx_t ctx;
  u8 e[UCL_SHA512_HASHSIZE];
  u8 mabc[3]={'a','b','c'};
  u8 mtwoblock512[]={"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
  u8 digest_void[]={0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e};
  u8 digest_abc[]={0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f};
  u8 digest_2blocks[]={0x8e,0x95,0x9b,0x75,0xda,0xe3,0x13,0xda,0x8c,0xf4,0xf7,0x28,0x14,0xfc,0x14,0x3f,0x8f,0x77,0x79,0xc6,0xeb,0x9f,0x7f,0xa1,0x72,0x99,0xae,0xad,0xb6,0x88,0x90,0x18,0x50,0x1d,0x28,0x9e,0x49,0x00,0xf7,0xe4,0x33,0x1b,0x99,0xde,0xc4,0xb5,0x43,0x3a,0xc7,0xd3,0x29,0xee,0xb6,0xdd,0x26,0x54,0x5e,0x96,0xe5,0x5b,0x87,0x4b,0xe9,0x09};
  u8 digest_1110[]={0x77,0xdd,0xd3,0xa5,0x42,0xe5,0x30,0xfd,0x04,0x7b,0x89,0x77,0xc6,0x57,0xba,0x6c,0xe7,0x2f,0x14,0x92,0xe3,0x60,0xb2,0xb2,0x21,0x2c,0xd2,0x64,0xe7,0x5e,0xc0,0x38,0x82,0xe4,0xff,0x05,0x25,0x51,0x7a,0xb4,0x20,0x7d,0x14,0xc7,0x0c,0x22,0x59,0xba,0x88,0xd4,0xd3,0x35,0xee,0x0e,0x7e,0x20,0x54,0x3d,0x22,0x10,0x2a,0xb1,0x78,0x8c};
  u8 digest_1120[]={0x2b,0xe2,0xe7,0x88,0xc8,0xa8,0xad,0xea,0xa9,0xc8,0x9a,0x7f,0x78,0x90,0x4c,0xac,0xea,0x6e,0x39,0x29,0x7d,0x75,0xe0,0x57,0x3a,0x73,0xc7,0x56,0x23,0x45,0x34,0xd6,0x62,0x7a,0xb4,0x15,0x6b,0x48,0xa6,0x65,0x7b,0x29,0xab,0x8b,0xeb,0x73,0x33,0x40,0x40,0xad,0x39,0xea,0xd8,0x14,0x46,0xbb,0x09,0xc7,0x07,0x04,0xec,0x70,0x79,0x52};
  u8 digest_1130[]={0x0e,0x67,0x91,0x0b,0xcf,0x0f,0x9c,0xcd,0xe5,0x46,0x4c,0x63,0xb9,0xc8,0x50,0xa1,0x2a,0x75,0x92,0x27,0xd1,0x6b,0x04,0x0d,0x98,0x98,0x6d,0x54,0x25,0x3f,0x9f,0x34,0x32,0x23,0x18,0xe5,0x6b,0x8f,0xeb,0x86,0xc5,0xfb,0x22,0x70,0xed,0x87,0xf3,0x12,0x52,0xf7,0xf6,0x84,0x93,0xee,0x75,0x97,0x43,0x90,0x9b,0xd7,0x5e,0x4b,0xb5,0x44};
  u8 digest_1220[]={0x4f,0x3f,0x09,0x5d,0x01,0x5b,0xe4,0xa7,0xa7,0xcc,0x0b,0x8c,0x04,0xda,0x4a,0xa0,0x9e,0x74,0x35,0x1e,0x3a,0x97,0x65,0x1f,0x74,0x4c,0x23,0x71,0x6e,0xbd,0x9b,0x3e,0x82,0x2e,0x50,0x77,0xa0,0x1b,0xaa,0x5c,0xc0,0xed,0x45,0xb9,0x24,0x9e,0x88,0xab,0x34,0x3d,0x43,0x33,0x53,0x9d,0xf2,0x1e,0xd2,0x29,0xda,0x6f,0x4a,0x51,0x4e,0x0f};
  u8 digest_10000[]={0xca,0x3d,0xff,0x61,0xbb,0x23,0x47,0x7a,0xa6,0x08,0x7b,0x27,0x50,0x82,0x64,0xa6,0xf9,0x12,0x6e,0xe3,0xa0,0x04,0xf5,0x3c,0xb8,0xdb,0x94,0x2e,0xd3,0x45,0xf2,0xf2,0xd2,0x29,0xb4,0xb5,0x9c,0x85,0x92,0x20,0xa1,0xcf,0x19,0x13,0xf3,0x42,0x48,0xe3,0x80,0x3b,0xab,0x65,0x0e,0x84,0x9a,0x3d,0x9a,0x70,0x9e,0xdc,0x09,0xae,0x4a,0x76};
  u8 digest_100041[]={0x32,0x9c,0x52,0xac,0x62,0xd1,0xfe,0x73,0x11,0x51,0xf2,0xb8,0x95,0xa0,0x04,0x75,0x44,0x5e,0xf7,0x4f,0x50,0xb9,0x79,0xc6,0xf7,0xbb,0x7c,0xae,0x34,0x93,0x28,0xc1,0xd4,0xcb,0x4f,0x72,0x61,0xa0,0xab,0x43,0xf9,0x36,0xa2,0x4b,0x00,0x06,0x51,0xd4,0xa8,0x24,0xfc,0xdd,0x57,0x7f,0x21,0x1a,0xef,0x8f,0x80,0x6b,0x16,0xaf,0xe8,0xaf};
  u8 digest_1005U[]={0x59,0xf5,0xe5,0x4f,0xe2,0x99,0xc6,0xa8,0x76,0x4c,0x6b,0x19,0x9e,0x44,0x92,0x4a,0x37,0xf5,0x9e,0x2b,0x56,0xc3,0xeb,0xad,0x93,0x9b,0x72,0x89,0x21,0x0d,0xc8,0xe4,0xc2,0x1b,0x97,0x20,0x16,0x5b,0x0f,0x4d,0x43,0x74,0xc9,0x0f,0x1b,0xf4,0xfb,0x4a,0x5a,0xce,0x17,0xa1,0x16,0x17,0x98,0x01,0x50,0x52,0x89,0x3a,0x48,0xc3,0xd1,0x61};
  u8 digest_1mil0[]={0xce,0x04,0x4b,0xc9,0xfd,0x43,0x26,0x9d,0x5b,0xbc,0x94,0x6c,0xbe,0xbc,0x3b,0xb7,0x11,0x34,0x11,0x15,0xcc,0x4a,0xbd,0xf2,0xed,0xbc,0x3f,0xf2,0xc5,0x7a,0xd4,0xb1,0x5d,0xeb,0x69,0x9b,0xda,0x25,0x7f,0xea,0x5a,0xef,0x9c,0x6e,0x55,0xfc,0xf4,0xcf,0x9d,0xc2,0x5a,0x8c,0x3c,0xe2,0x5f,0x2e,0xfe,0x90,0x90,0x83,0x79,0xbf,0xf7,0xed};
  u8 digest_5a[]={0xda,0x17,0x22,0x79,0xf3,0xeb,0xbd,0xa9,0x5f,0x6b,0x6e,0x1e,0x5f,0x0e,0xbe,0xc6,0x82,0xc2,0x5d,0x3d,0x93,0x56,0x1a,0x16,0x24,0xc2,0xfa,0x90,0x09,0xd6,0x4c,0x7e,0x99,0x23,0xf3,0xb4,0x6b,0xca,0xf1,0x1d,0x39,0xa5,0x31,0xf4,0x32,0x97,0x99,0x2b,0xa4,0x15,0x5c,0x7e,0x82,0x7b,0xd0,0xf1,0xe1,0x94,0xae,0x7e,0xd6,0xde,0x4c,0xac};
  u8 digest_1090[]={0x14,0xb1,0xbe,0x90,0x1c,0xb4,0x35,0x49,0xb4,0xd8,0x31,0xe6,0x1e,0x5f,0x9d,0xf1,0xc7,0x91,0xc8,0x5b,0x50,0xe8,0x5f,0x9d,0x6b,0xc6,0x41,0x35,0x80,0x4a,0xd4,0x3c,0xe8,0x40,0x27,0x50,0xed,0xbe,0x4e,0x5c,0x0f,0xc1,0x70,0xb9,0x9c,0xf7,0x8b,0x9f,0x4e,0xcb,0x9c,0x7e,0x02,0xa1,0x57,0x91,0x1d,0x1b,0xd1,0x83,0x2d,0x76,0x78,0x4f};
  u8 digest_42[]={0xfd,0x05,0xe1,0x3e,0xb7,0x71,0xf0,0x51,0x90,0xbd,0x97,0xd6,0x26,0x47,0x15,0x7e,0xa8,0xf1,0xf6,0x94,0x9a,0x52,0xbb,0x6d,0xaa,0xed,0xba,0xd5,0xf5,0x78,0xec,0x59,0xb1,0xb8,0xd6,0xc4,0xa7,0xec,0xb2,0xfe,0xca,0x68,0x92,0xb4,0xdc,0x13,0x87,0x71,0x67,0x0a,0x0f,0x3b,0xd5,0x77,0xee,0xa3,0x26,0xae,0xd4,0x0a,0xb7,0xdd,0x58,0xb1};
  u8 tab[1005];
#ifdef VERBOSE
  PRINTF("TEST SHA512\n");
#endif
  ucl_sha512(e,mabc,0);
#ifdef VERBOSE
  PRINTF("sha512(void):");
#endif
  if(memcmp(e,digest_void,64)!=0)
    return(UCL_ERROR);
  ucl_sha512(e,mabc,3);
#ifdef VERBOSE
  PRINTF("sha512(abc):");
#endif
  if(memcmp(e,digest_abc,64)!=0)
    return(UCL_ERROR);
  ucl_sha512(e,mtwoblock512,112);
#ifdef VERBOSE
  PRINTF("sha512(2blocks):");
#endif
  if(memcmp(e,digest_2blocks,64)!=0)
    return(UCL_ERROR);
  for(i=0;i<1000;i++)
    tab[i]=0;
  ucl_sha512(e,tab,111);
#ifdef VERBOSE
  PRINTF("sha512(111-0):");
#endif
  if(memcmp(e,digest_1110,64)!=0)
    return(UCL_ERROR);

  ucl_sha512(e,tab,112);
#ifdef VERBOSE
  PRINTF("sha512(112-0):");
#endif
  if(memcmp(e,digest_1120,64)!=0)
    return(UCL_ERROR);

  ucl_sha512(e,tab,113);
#ifdef VERBOSE
  PRINTF("sha512(113-0):");
#endif
  if(memcmp(e,digest_1130,64)!=0)
    return(UCL_ERROR);
  ucl_sha512(e,tab,122);
#ifdef VERBOSE
  PRINTF("sha512(122-0):");
#endif
  //#5) 122 bytes of zeros
  if(memcmp(e,digest_1220,64)!=0)
    return(UCL_ERROR);

  ucl_sha512(e,tab,1000);
#ifdef VERBOSE
  PRINTF("sha512(1000-0):");
#endif
  //#6) 1000 bytes of zeros
  if(memcmp(e,digest_10000,64)!=0)
    return(UCL_ERROR);

  for(i=0;i<1000;i++)
    tab[i]='A';
  ucl_sha512(e,tab,1000);
#ifdef VERBOSE
  PRINTF("sha512(1000-A):");
#endif
  //#7) 1000 bytes of 0x41 �A�
  if(memcmp(e,digest_100041,64)!=0)
    return(UCL_ERROR);

  for(i=0;i<1005;i++)
    tab[i]='U';
  ucl_sha512(e,tab,1005);
#ifdef VERBOSE
  PRINTF("sha512(1005-U):");
#endif
  //#8) 1005 bytes of 0x55 �U�
  if(memcmp(e,digest_1005U,64)!=0)
    return(UCL_ERROR);

  for(i=0;i<1000;i++)
    tab[i]=0;
  ucl_sha512_init(&ctx);
  for(i=0;i<1000;i++)
    ucl_sha512_core(&ctx,tab,1000);
  ucl_sha512_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha512(1mil-0):");
#endif
  //#9) 1000000 bytes of zeros
  if(memcmp(e,digest_1mil0,64)!=0)
    return(UCL_ERROR);

  for(i=0;i<512;i++)
    tab[i]='Z';
  ucl_sha512_init(&ctx);
  for(i=0;i<1048576;i++)
    {
    ucl_sha512_core(&ctx,tab,512);
    }
  ucl_sha512_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha512(2^29-Z):");
#endif
  //#10) 0x20000000 (536870912) bytes of 0x5a �Z�
  if(memcmp(e,digest_5a,64)!=0)
    return(UCL_ERROR);

  for(i=0;i<520;i++)
    tab[i]=0;
  ucl_sha512_init(&ctx);
  for(i=0;i<2097152;i++)
    {
      ucl_sha512_core(&ctx,tab,520);
    }
  ucl_sha512_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha512(2^24*5*13-0):");
#endif
  //#11) 0x41000000 (1090519040) bytes of zeros
  if(memcmp(e,digest_1090,64)!=0)
    return(UCL_ERROR);

  for(i=0;i<118;i++)
    tab[i]='B';
  ucl_sha512_init(&ctx);
  for(i=0;i<13649261;i++)
    ucl_sha512_core(&ctx,tab,118);
  ucl_sha512_finish(e,&ctx);
#ifdef VERBOSE
  PRINTF("sha512(2*59*13649261-'B'):");
#endif
  //#12) 0x6000003e (1610612798) bytes of 0x42 �B�
  if(memcmp(e,digest_42,64)!=0)
    return(UCL_ERROR);
  return(UCL_OK);
}

void test_sha(void)
{
  if(UCL_OK==test_sia256())
    PRINTF("SIA256 OK\n");
  if(UCL_OK==test_sha256())
    PRINTF("SHA256 OK\n");
  if(UCL_OK==test_sha384())
    PRINTF("SHA384 OK\n");
  if(UCL_OK==test_sha512())
    PRINTF("SHA512 OK\n");
  if(UCL_OK==test_sha3())
    PRINTF("SHA3 OK\n");
}
