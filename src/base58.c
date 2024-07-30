#include "hashs.h"
#include <string.h>
#include <stdint.h>

static const int8_t b58digits_map[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool base58_encode(char *b58, size_t *b58sz, const uint8_t *data, size_t binsz)
{
    int32_t i, j, high, zcount = 0;
    size_t size;

    while (zcount < (int32_t)binsz && !data[zcount])
        ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    if (size > BASE58_DECODE_MAXLEN) {
        return false;
    }

    uint8_t buf[BASE58_DECODE_MAXLEN] = {0};

    for (i = zcount, high = (int32_t)size - 1; i < (int32_t)binsz; ++i, high = j)
    {
        int32_t carry = data[i];
        for (j = size - 1; (j > high) || carry; --j)
        {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
            if (j < 0) return false; // Prevent underflow
        }
    }

    for (j = 0; j < (int32_t)size && !buf[j]; ++j);

    if (*b58sz <= zcount + size - j)
    {
        *b58sz = zcount + size - j + 1;
        return false;
    }

    if (zcount)
        memset(b58, '1', zcount);
    for (i = zcount; j < (int32_t)size; ++i, ++j)
        b58[i] = b58digits_ordered[buf[j]];
    b58[i] = '\0';
    *b58sz = i + 1;

    return true;
}

bool base58_decode(uint8_t *bin, size_t *binszp, const char *b58, size_t b58sz)
{
    size_t binsz = *binszp;
    const unsigned char *b58u = (const unsigned char*)b58;
    size_t outisz = BASE58_DECODE_MAXLEN / 4;
    uint32_t outi[BASE58_DECODE_MAXLEN / 4] = {0};
    size_t i, j;
    uint8_t bytesleft = binsz % 4;
    uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
    unsigned zerocount = 0;

    if (!b58sz)
        b58sz = strlen(b58);

    // Leading zeros, just count
    for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
        ++zerocount;

    for ( ; i < b58sz; ++i)
    {
        if (b58u[i] & 0x80)
            return false;
        if (b58u[i] >= sizeof(b58digits_map) || b58digits_map[b58u[i]] == -1)
            return false;
        uint32_t c = (unsigned)b58digits_map[b58u[i]];
        for (j = outisz; j--; )
        {
            uint64_t t = ((uint64_t)outi[j]) * 58 + c;
            c = (t & 0x3f00000000) >> 32;
            outi[j] = t & 0xffffffff;
        }
        if (c)
            return false;
        if (outi[0] & zeromask)
            return false;
    }

    if (binsz > BASE58_DECODE_MAXLEN)
        return false;

    j = 0;
    switch (bytesleft) {
        case 3:
            bin[j++] = (outi[0] &   0xff0000) >> 16;
            // fallthrough
        case 2:
            bin[j++] = (outi[0] &     0xff00) >>  8;
            // fallthrough
        case 1:
            bin[j++] = (outi[0] &       0xff);
            // fallthrough
        default:
            break;
    }

    for (; j < binsz && j < outisz * 4; ++j)
    {
        bin[j] = (outi[j/4] >> (8 * (3 - j%4))) & 0xff;
    }

    // Count canonical base58 byte count
    for (i = 0; i < binsz; ++i)
    {
        if (bin[i])
            break;
        --*binszp;
    }
    *binszp += zerocount;

    return true;
}
