/**
 * An extremely minimal crypto library for Arduino devices.
 * 
 * The SHA256 and AES implementations are derived from axTLS 
 * (http://axtls.sourceforge.net/), Copyright (c) 2008, Cameron Rich.
 * 
 * Ported and refactored by Chris Ellis 2016.
 * pkcs7 padding routines added by Mike Killewald Nov 26, 2017 (adopted from https://github.com/spaniakos/AES).
 * 
 */

#include <Crypto.h>

/**
 * Byte order helpers
 */


//#if BYTE_ORDER == BIG_ENDIAN
/*
inline static uint16_t crypto_htons(uint16_t x)
{
    return x;
}
 
inline static uint16_t crypto_ntohs(uint16_t x)
{
    return x;
}

inline static uint32_t crypto_htonl(uint32_t x)
{
    return x;
}

inline static uint32_t crypto_ntohl(uint32_t x)
{
    return x;
}
*/
//#else

inline static uint16_t crypto_htons(uint16_t x)
{
    return (
            ((x & 0xff)   << 8) | 
            ((x & 0xff00) >> 8)
           );
}
 
inline static uint16_t crypto_ntohs(uint16_t x)
{
    return (
            ((x & 0xff)   << 8) | 
            ((x & 0xff00) >> 8)
           );
}

inline static uint32_t crypto_htonl(uint32_t x)
{
    return (
            ((x & 0xff)         << 24) | 
            ((x & 0xff00)       << 8)  | 
            ((x & 0xff0000UL)   >> 8)  | 
            ((x & 0xff000000UL) >> 24)
           );
}

inline static uint32_t crypto_ntohl(uint32_t x)
{
    return (
            ((x & 0xff)         << 24) | 
            ((x & 0xff00)       << 8)  | 
            ((x & 0xff0000UL)   >> 8)  | 
            ((x & 0xff000000UL) >> 24)
           );
}

//#endif

#define GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ((uint32_t) (b)[(i)    ] << 24)       \
        | ((uint32_t) (b)[(i) + 1] << 16)       \
        | ((uint32_t) (b)[(i) + 2] <<  8)       \
        | ((uint32_t) (b)[(i) + 3]      );      \
}

#define PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (byte) ((n) >> 24);       \
    (b)[(i) + 1] = (byte) ((n) >> 16);       \
    (b)[(i) + 2] = (byte) ((n) >>  8);       \
    (b)[(i) + 3] = (byte) ((n)      );       \
}

static const byte sha256_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * Initialize the SHA256 hash
 */
SHA256::SHA256()
{
    total[0] = 0;
    total[1] = 0;
    state[0] = 0x6A09E667;
    state[1] = 0xBB67AE85;
    state[2] = 0x3C6EF372;
    state[3] = 0xA54FF53A;
    state[4] = 0x510E527F;
    state[5] = 0x9B05688C;
    state[6] = 0x1F83D9AB;
    state[7] = 0x5BE0CD19;
}

void SHA256::SHA256_Process(const byte digest[64])
{
    uint32_t temp1, temp2, W[64];
    uint32_t A, B, C, D, E, F, G, H;

    GET_UINT32(W[0],  digest,  0);
    GET_UINT32(W[1],  digest,  4);
    GET_UINT32(W[2],  digest,  8);
    GET_UINT32(W[3],  digest, 12);
    GET_UINT32(W[4],  digest, 16);
    GET_UINT32(W[5],  digest, 20);
    GET_UINT32(W[6],  digest, 24);
    GET_UINT32(W[7],  digest, 28);
    GET_UINT32(W[8],  digest, 32);
    GET_UINT32(W[9],  digest, 36);
    GET_UINT32(W[10], digest, 40);
    GET_UINT32(W[11], digest, 44);
    GET_UINT32(W[12], digest, 48);
    GET_UINT32(W[13], digest, 52);
    GET_UINT32(W[14], digest, 56);
    GET_UINT32(W[15], digest, 60);

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                              \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];

    P(A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98);
    P(H, A, B, C, D, E, F, G, W[ 1], 0x71374491);
    P(G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF);
    P(F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5);
    P(E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B);
    P(D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1);
    P(C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4);
    P(B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5);
    P(A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98);
    P(H, A, B, C, D, E, F, G, W[ 9], 0x12835B01);
    P(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
    P(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
    P(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
    P(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
    P(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
    P(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
    P(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
    P(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
    P(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
    P(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
    P(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
    P(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
    P(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
    P(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
    P(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
    P(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
    P(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
    P(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
    P(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
    P(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
    P(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
    P(B, C, D, E, F, G, H, A, R(31), 0x14292967);
    P(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
    P(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
    P(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
    P(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
    P(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
    P(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
    P(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
    P(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
    P(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
    P(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
    P(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
    P(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
    P(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
    P(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
    P(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
    P(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
    P(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
    P(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
    P(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
    P(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
    P(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
    P(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
    P(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
    P(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
    P(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
    P(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
    P(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
    P(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
    P(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
    P(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
    P(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
    P(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
    state[5] += F;
    state[6] += G;
    state[7] += H;
#if defined ESP8266
    ESP.wdtFeed();
#endif
}

/**
 * Accepts an array of octets as the next portion of the message.
 */
void SHA256::doUpdate(const byte * msg, int len)
{
    uint32_t left = total[0] & 0x3F;
    uint32_t fill = 64 - left;

    total[0] += len;
    total[0] &= 0xFFFFFFFF;

    if (total[0] < len)
        total[1]++;

    if (left && len >= fill)
    {
        memcpy((void *) (buffer + left), (void *) msg, fill);
        SHA256::SHA256_Process(buffer);
        len -= fill;
        msg  += fill;
        left = 0;
    }

    while (len >= 64)
    {
        SHA256::SHA256_Process(msg);
        len -= 64;
        msg  += 64;
    }

    if (len)
    {
        memcpy((void *) (buffer + left), (void *) msg, len);
    }
}

/**
 * Return the 256-bit message digest into the user's array
 */
void SHA256::doFinal(byte *digest)
{
    uint32_t last, padn;
    uint32_t high, low;
    byte msglen[8];

    high = (total[0] >> 29)
         | (total[1] <<  3);
    low  = (total[0] <<  3);

    PUT_UINT32(high, msglen, 0);
    PUT_UINT32(low,  msglen, 4);

    last = total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    SHA256::doUpdate(sha256_padding, padn);
    SHA256::doUpdate(msglen, 8);

    PUT_UINT32(state[0], digest,  0);
    PUT_UINT32(state[1], digest,  4);
    PUT_UINT32(state[2], digest,  8);
    PUT_UINT32(state[3], digest, 12);
    PUT_UINT32(state[4], digest, 16);
    PUT_UINT32(state[5], digest, 20);
    PUT_UINT32(state[6], digest, 24);
    PUT_UINT32(state[7], digest, 28);
#if defined ESP8266
    ESP.wdtFeed();
#endif
}

bool SHA256::matches(const byte *expected)
{
    byte theDigest[SHA256_SIZE];
    doFinal(theDigest);
    for (byte i = 0; i < SHA256_SIZE; i++)
    {
        if (expected[i] != theDigest[i])
            return false;
    }
#if defined ESP8266
    ESP.wdtFeed();
#endif
    return true;
}

/******************************************************************************/

#define rot1(x) (((x) << 24) | ((x) >> 8))
#define rot2(x) (((x) << 16) | ((x) >> 16))
#define rot3(x) (((x) <<  8) | ((x) >> 24))

/* 
 * This cute trick does 4 'mul by two' at once.  Stolen from
 * Dr B. R. Gladman <brg@gladman.uk.net> but I'm sure the u-(u>>7) is
 * a standard graphics trick
 * The key to this is that we need to xor with 0x1b if the top bit is set.
 * a 1xxx xxxx   0xxx 0xxx First we mask the 7bit,
 * b 1000 0000   0000 0000 then we shift right by 7 putting the 7bit in 0bit,
 * c 0000 0001   0000 0000 we then subtract (c) from (b)
 * d 0111 1111   0000 0000 and now we and with our mask
 * e 0001 1011   0000 0000
 */
#define mt  0x80808080
#define ml  0x7f7f7f7f
#define mh  0xfefefefe
#define mm  0x1b1b1b1b
#define mul2(x,t)	((t)=((x)&mt), \
			((((x)+(x))&mh)^(((t)-((t)>>7))&mm)))

#define inv_mix_col(x,f2,f4,f8,f9) (\
			(f2)=mul2(x,f2), \
			(f4)=mul2(f2,f4), \
			(f8)=mul2(f4,f8), \
			(f9)=(x)^(f8), \
			(f8)=((f2)^(f4)^(f8)), \
			(f2)^=(f9), \
			(f4)^=(f9), \
			(f8)^=rot3(f2), \
			(f8)^=rot2(f4), \
			(f8)^rot1(f9))


static const unsigned char Rcon[30]=
{
	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,
	0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a,0x2f,
	0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,0xd4,
	0xb3,0x7d,0xfa,0xef,0xc5,0x91,
};


/**
 * Decrypt a single block (16 bytes) of data
 */

#if defined ESP8266 || defined ESP32
/**
 * ESP8266 and ESP32 specific hardware true random number generator.
 * 
 * Acording to the ESP32 documentation, you should not call the tRNG 
 * faster than 5MHz
 * 
 */

void RNG::fill(uint8_t *dst, unsigned int length)
{
    // ESP8266 and ESP32 only
    for (int i = 0; i < length; i++)
    {
        dst[i] = get();
    }
#if defined ESP8266
    ESP.wdtFeed();
#endif
}

byte RNG::get()
{
#if defined ESP32
    // ESP32 only
    uint32_t* randReg = (uint32_t*) 0x3FF75144;
    return (byte) *randReg;
#elif defined ESP8266
    // ESP8266 only
    uint32_t* randReg = (uint32_t*) 0x3FF20E44L;
    return (byte) *randReg;
#else
    // NOT SUPPORTED
    return 0;
#endif
}

uint32_t RNG::getLong()
{
#if defined ESP32
    // ESP32 only
    uint32_t* randReg = (uint32_t*) 0x3FF75144;
    return (byte) *randReg;
#elif defined ESP8266
    // ESP8266 only
    uint32_t* randReg = (uint32_t*) 0x3FF20E44L;
    return *randReg;
#else
    // NOT SUPPORTED
    return 0;
#endif
}
#endif


/**
 * SHA256 HMAC
 */

SHA256HMAC::SHA256HMAC(const byte *key, unsigned int keyLen)
{
    // sort out the key
    byte theKey[SHA256HMAC_BLOCKSIZE];
    memset(theKey, 0, SHA256HMAC_BLOCKSIZE);
    if (keyLen > SHA256HMAC_BLOCKSIZE)
    {
        // take a hash of the key
        SHA256 keyHahser;
        keyHahser.doUpdate(key, keyLen);
        keyHahser.doFinal(theKey);
    }
    else 
    {
        // we already set the buffer to 0s, so just copy keyLen
        // bytes from key
        memcpy(theKey, key, keyLen);
    }
    // explicitly zero pads
    memset(_innerKey, 0, SHA256HMAC_BLOCKSIZE);
    memset(_outerKey, 0, SHA256HMAC_BLOCKSIZE);
    // compute the keys
    blockXor(theKey, _innerKey, HMAC_IPAD, SHA256HMAC_BLOCKSIZE);
    blockXor(theKey, _outerKey, HMAC_OPAD, SHA256HMAC_BLOCKSIZE);
    // start the intermediate hash
    _hash.doUpdate(_innerKey, SHA256HMAC_BLOCKSIZE);
}

void SHA256HMAC::doUpdate(const byte *msg, unsigned int len)
{
    _hash.doUpdate(msg, len);
}

void SHA256HMAC::doFinal(byte *digest)
{
    // compute the intermediate hash
    byte interHash[SHA256_SIZE];
    _hash.doFinal(interHash);
    // compute the final hash
    SHA256 finalHash;
    finalHash.doUpdate(_outerKey, SHA256HMAC_BLOCKSIZE);
    finalHash.doUpdate(interHash, SHA256_SIZE);
    finalHash.doFinal(digest);
}

bool SHA256HMAC::matches(const byte *expected)
{
    byte theDigest[SHA256_SIZE];
    doFinal(theDigest);
    for (byte i = 0; i < SHA256_SIZE; i++)
    {
        if (expected[i] != theDigest[i])
            return false;
    }
    return true;
}

void SHA256HMAC::blockXor(const byte *in, byte *out, byte val, byte len)
{
    for (byte i = 0; i < len; i++)
    {
        out[i] = in[i] ^ val;
    }
}


