#pragma once
#include "pch.h"

#pragma pack(push, 1)
struct RadiotapHdr {
    uint8_t ver;
    uint8_t pad;
    uint16_t len;
    uint32_t pf;
};
#pragma pack(pop)

RadiotapHdr createMinimalRt();