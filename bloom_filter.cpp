#include "but_header.hpp"

BloomFilter::BloomFilter()
{
    for (int i = 0; i < BLOOM_BITS / 8; i++)
        bits[i] = 0;
}

unsigned int BloomFilter::hash1(const char* url)
{
    unsigned int h = 5381;
    for (int i = 0; url[i] != '\0'; i++)
        h = h * 33 + (unsigned char)url[i];
    return h % BLOOM_BITS;
}

unsigned int BloomFilter::hash2(const char* url)
{
    unsigned int h = 0;
    for (int i = 0; url[i] != '\0'; i++)
        h = (unsigned char)url[i] + (h << 6) + (h << 16) - h;
    return h % BLOOM_BITS;
}

unsigned int BloomFilter::hash3(const char* url)
{
    unsigned int h = 2166136261u;
    for (int i = 0; url[i] != '\0'; i++) {
        h ^= (unsigned char)url[i];
        h *= 16777619u;
    }
    return h % BLOOM_BITS;
}

void BloomFilter::setBit(unsigned int i)
{
    bits[i / 8] |= (unsigned char)(1u << (i % 8));
}

bool BloomFilter::getBit(unsigned int i)
{
    return (bits[i / 8] & (1u << (i % 8))) != 0;
}

void BloomFilter::insert(const char* url)
{
    setBit(hash1(url));
    setBit(hash2(url));
    setBit(hash3(url));
}

bool BloomFilter::check(const char* url)
{
    return getBit(hash1(url)) && getBit(hash2(url)) && getBit(hash3(url));
}
