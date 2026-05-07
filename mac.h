#pragma once
#include "pch.h"

#pragma pack(push, 1)
struct Mac {
    uint8_t m_[6];

    Mac();

    explicit Mac(const std::string& s);

    std::string toString() const;

    bool operator < (const Mac& r) const;

    static Mac broadcast();
};
#pragma pack(pop)