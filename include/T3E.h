#ifndef T3E_H
#define T3E_H

#include <tuple>

namespace t3e
{
    std::tuple<bool, uint64_t, uint64_t> getTrustedTime();
}

#endif