#include "capture.h"

#include <iostream>
#include <fstream>
#include <functional>
#include <memory>
#include <math.h>

#include "network_packet.h"

namespace CapJSON
{

PacketCapture::PacketCapture()
{
    //create a pcap file to store the packets
#ifdef _WIN32
    std::string file_path = "../../out/outfile.pcap";
#else
    std::string file_path = "../out/outfile.pcap";
#endif

    p_writer = std::make_unique<Tins::PacketWriter>(
            file_path,
            Tins::DataLinkType<Tins::EthernetII>()
            );

    packet_count_ = 0;
    json_objects_.reserve(100);

};

void PacketCapture::WriteToFile()
{
    std::chrono::microseconds us = initial_timestamp_;
    us /= 1000;
    std::cout << "100 packets reached, init timestamp is: " << std::to_string(us.count()) << "\n";
    //write packets to output files

//temporary, have to find a better way to do this
#ifdef _WIN32
    std::string path = "../../out/packet-" + std::to_string(us.count());
#else
    std::string path = "../out/packet-" + std::to_string(us.count());
#endif

    std::ofstream ofs(path);

    for(JSON j: json_objects_)
        ofs << j << "\n";

    //clear the json object vector 
    json_objects_.clear();

    // reset the packet count
    packet_count_ = 0;
}

void PacketCapture::SetInitialTimestamp(const Tins::Timestamp& ts) 
{
    initial_timestamp_ = ts; 
}

bool PacketCapture::Callback(Tins::PDU& pdu)
{
    // used to write output to pcap file to view in wireshark
    // and to extract the timestamp for the captured packet
    Tins::Packet packet(pdu);
    const Tins::Timestamp& ts = packet.timestamp();

    // store an initial timestamp that will be appended to the 
    // output file name when writing the packets
    if(packet_count_ == 0)
        SetInitialTimestamp(ts);

    // extract pdu and timestamp into a separate network packet structure
    NetworkPacket np(pdu, ts);

    //generate JSON object from network packet
    //JSON j(np);

    //create JSON object and store it in vector
    json_objects_.emplace_back(np);
    
    // Write the packets to the file 
    if (packet_count_ == max_packets_) {
        WriteToFile();
        return true;
    }

    packet_count_++;

    //std::cout << j << "\n";


    p_writer->write(packet);

    return true;
}

void PacketCapture::RunSniffer(Tins::Sniffer& sniffer)
{
    sniffer.sniff_loop(std::bind(
                &PacketCapture::Callback,
                this,
                std::placeholders::_1
                )
            );
}

}
