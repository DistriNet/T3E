#pragma once

#ifndef DELAYEDTESTSTRUCT_H
#define DELAYEDTESTSTRUCT_H

#if __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif
typedef struct TestEntry
{
    uint64_t seq;
    uint64_t trustedTime;
    uint64_t counterTime;
} TestEntry;

#if __cplusplus

inline TestEntry operator+(TestEntry const& a, TestEntry const& b)
{
    return {0, a.trustedTime + b.trustedTime, a.counterTime + b.counterTime};
}

inline TestEntry operator/(TestEntry const& a, uint64_t b)
{
    return {0, a.trustedTime / b, a.counterTime / b};
}

#endif

#endif