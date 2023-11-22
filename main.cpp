#include <iostream>
#include <pcap.h>
#include <cstdlib>
#include <cstring>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_pcap_file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);

    if (pcap == NULL) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    const u_char *packet;
    struct pcap_pkthdr header;
    struct timeval lastTimestamp;
    double longestGap = 0.0;
    int packetNumber = 0;
    int longestGapStartLine = 0;
    int longestGapEndLine = 0;
    bool firstPacket = true;

    while ((packet = pcap_next(pcap, &header)) != NULL) {
        packetNumber++;
        if (firstPacket) {
            lastTimestamp = header.ts;
            firstPacket = false;
            continue;
        }

        double gap = (header.ts.tv_sec - lastTimestamp.tv_sec) + 
                     (header.ts.tv_usec - lastTimestamp.tv_usec) / 1000000.0;

        if (gap > longestGap) {
            longestGap = gap;
            longestGapStartLine = packetNumber - 1;
            longestGapEndLine = packetNumber;
        }

        lastTimestamp = header.ts;
    }

    pcap_close(pcap);

    std::cout << "Longest gap: " << longestGap << " seconds, between packet numbers " 
              << longestGapStartLine << " and " << longestGapEndLine << std::endl;

    return 0;
}
