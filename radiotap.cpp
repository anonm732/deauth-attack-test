#include "pch.h"
#include "radiotap.h"

RadiotapHdr createMinimalRt() {
    RadiotapHdr hdr;
    hdr.ver = 0;
    hdr.pad = 0;
    hdr.len = sizeof(RadiotapHdr);
    hdr.pf = 0;

    return hdr;
}