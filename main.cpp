#include "pcap_helper.h"
int main()
{
    Pcap_Helper *pcap = Pcap_Helper::getInstance();
    pcap->init("../test.pcap");
    pcap->handlePcapLoop();
    delete pcap;
    return 0;
}