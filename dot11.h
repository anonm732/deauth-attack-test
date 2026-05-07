#pragma once
#include "pch.h"
#include "mac.h"

// Frame Control Field
static const uint16_t FC_DEAUTH = 0x00C0;    // subtype 12 : Deauth
static const uint16_t FC_AUTH = 0x00B0;      // subtype 11 : Auth
static const uint16_t FC_DISASSOC = 0x00A0; // subtype 10 : Disassoc

static const uint16_t REASON_CLASS3 = 0x0007;
static const uint16_t REASON_UNKNOWN = 0x4D00;

#pragma pack(push, 1)
struct Dot11MgmtHdr {
    uint16_t fc;
    uint16_t duration;
    Mac addr_1;         // Receiver Addr
    Mac addr_2;         // Transmitter Addr
    Mac addr_3;         // BSSID
    uint16_t seq;       // FragNum(4b) + SeqNum(12b)
};

struct Dot11Deauth {
    Dot11MgmtHdr hdr;
    uint16_t reason;
};
typedef Dot11Deauth* PDot11Deauth;
#pragma pack(pop)