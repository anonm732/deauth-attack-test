#include "pch.h"
#include "radiotap.h"

void RadiotapHdr::initMinimalRt() {
    ver = 0;
    pad = 0;
    len = sizeof(RadiotapHdr);
    pf = 0;
}