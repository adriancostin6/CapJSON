#include "capture.h"

#include <iostream>
#include <fstream>
#include <functional>
#include <memory>
#include <math.h>

#include "network_packet.h"
#include "json.h"

namespace CapJSON
{

Capture::Capture(const std::string& filename)
{
    //create a pcap file to store the packets
#ifdef _WIN32
    std::string file_path = "../../out/" + filename + ".pcap";
#else
    std::string file_path = "../out/" + filename + ".pcap";
#endif

    p_writer = std::make_unique<Tins::PacketWriter>(
            file_path,
            Tins::DataLinkType<Tins::EthernetII>()
            );

};

bool Capture::callback(Tins::PDU& pdu)
{
    //make a network packet
    NetworkPacket np(pdu);

    //generate JSON object from network packet
    JSON j(np);

    std::cout << j << "\n";

    // store packets in pcap file as well to view in wireshark
    Tins::Packet packet(pdu);

    p_writer->write(packet);

    return true;
}

void Capture::run_sniffer(Tins::Sniffer& sniffer)
{
    sniffer.sniff_loop(std::bind(
                &Capture::callback,
                this,
                std::placeholders::_1
                )
            );
}

}
