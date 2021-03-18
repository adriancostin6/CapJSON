#include "capture.h"

#include <fstream>
#include <functional>


using namespace Tins;

Capture::Capture(const std::string& filename)
{
    //create a pcap file to store the packets
#ifdef _WIN32
    std::string file_path = "../../out/" + filename + ".pcap";
#else
    std::string file_path = "../out/" + filename + ".pcap";
#endif

    p_writer = std::make_unique<PacketWriter>(file_path,DataLinkType<EthernetII>());

};

bool Capture::callback(const PDU& pdu)
{
    //store the PDU in a Packet object for writing it to a PCAP file
    //Packet packet = pdu;
    Packet packet(pdu);

    //get IP, UDP and RAW payload data
    //const IP& ip = pdu.rfind_pdu<IP>();
    //const UDP& udp = pdu.rfind_pdu<UDP>();
    //const RawPDU& raw = udp.rfind_pdu<RawPDU>();

    p_writer->write(packet);
    
    return true;
}

void Capture::run_sniffer(Sniffer& sniffer)
{
    sniffer.sniff_loop(std::bind(
                &Capture::callback,
                this,
                std::placeholders::_1
                )
            );
}
