#pragma once
#include "pch.h"
#include "mac.h"
#include "radiotap.h"
#include "dot11.h"

struct DeauthPkt {
    pcap_t* pcap_;
    Mac apMac_;
    Mac stMac_;
    bool authMode_;

    DeauthPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac, bool authMode);

    std::vector<uint8_t> createDeauth(const Mac& stc, const Mac& dst, const Mac& bssid, uint16_t seq);
};
