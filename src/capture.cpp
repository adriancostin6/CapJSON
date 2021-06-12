#include "capture.h"

#include <iostream>
#include <fstream>
#include <functional>
#include <memory>
#include <math.h>
#include <sstream>
#include <iomanip>

#include "network_packet.h"

namespace CapJSON
{

PacketCapture::PacketCapture(const std::string& path, bool gen_pcap) :
    packet_count_(1), output_count_(0), output_path_(path), gen_pcap_(gen_pcap)
{
    //create a pcap file to store the packets
    if (gen_pcap_) {
#ifdef _WIN32
    std::string file_path = "../../out/outfile.pcap";
#else
    std::string file_path = "../out/outfile.pcap";
#endif

    p_writer = std::make_unique<Tins::PacketWriter>(
            file_path,
            Tins::DataLinkType<Tins::EthernetII>()
            );
     } 

    json_objects_.reserve(100);

};

void PacketCapture::WriteToFile()
{
    std::chrono::microseconds us = initial_timestamp_;
    us /= 1000;
    std::cout << "100 packets reached, init timestamp is: " << std::to_string(us.count()) << "\n";

    // make output file path
    std::string of_path = output_path_ + "/packets-" + std::to_string(us.count());

    std::ofstream ofs(of_path);

    for(JSON j: json_objects_)
        ofs << j << "\n";

    //clear the json object vector 
    json_objects_.clear();

    // reset the output count
    output_count_ = 0;
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

    //so we don't accidentally skip packets
    if(gen_pcap_)
        p_writer->write(packet);

    const Tins::Timestamp& ts = packet.timestamp();

    // store an initial timestamp that will be appended to the 
    // output file name when writing the packets
    if(output_count_ == 0)
        SetInitialTimestamp(ts);

    // extract pdu and timestamp into a separate network packet structure
    NetworkPacket np(pdu, ts, packet_count_);
    packet_count_++;

    //create JSON object and store it in vector
    json_objects_.emplace_back(np);

    // write packets to file(resets output counter) and skip to the next callback
    if (output_count_ == max_packets_) {
        WriteToFile();
        return true;
    }

    // increment output counter and go to the next callback
    output_count_++;
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
    //const Tins::EthernetII* eth = pdu.find_pdu<Tins::EthernetII>();
    //const Tins::IP* ip = pdu.find_pdu<Tins::IP>();
    //const Tins::IPv6* ipv6 = pdu.find_pdu<Tins::IPv6>();
    //const Tins::TCP* tcp  = pdu.find_pdu<Tins::TCP>();
    //const Tins::UDP* udp = pdu.find_pdu<Tins::UDP>();
    //const Tins::RawPDU* raw = nullptr;
    //if(eth){
    //    std::cout << "Ethernet layer: Ethernet header size is:" << eth->header_size()
    //        <<" Ethernet trailer size is:" << eth->trailer_size() << "\n"; 
    //    // what if we have and ARP packet or a payload that comes over ETH dirrectly?
    //    // if we don't have an IP layer
    //}

    //if (!ip && !ipv6)
    //    std::cout << "NO IP LAYER?";

    //if(ip) { 
    //    //std::cout << "Total packet length is:" << ip->tot_len() + eth->header_size() << "\n";
    //    std::cout << "Total packet length is:"
    //        << ip->tot_len() + eth->header_size() + eth->trailer_size() << "\n";
    //    std::cout << "IP layer: IP length is:" << ip->tot_len()<< "\n";
    //}

    //if(ipv6) { 
    //    // the fixed IPV6 header size is 40 bytes if we use the payload length
    //    // payload length includes the extension headers
    //    // header size includes the extension headers
    //    // we use 40 so we don't get duplicate extension headers
    //    std::cout << "Total packet length is:" 
    //        << 40 + ipv6->payload_length() + eth->header_size() + eth->trailer_size() << "\n";
    //    std::cout << "IPv6 layer: IPv6 payload length:" << ipv6->payload_length()
    //        << " IPv6 header size:" << ipv6->header_size() << "\n";

    //}

    //if(tcp) {
    //    std::cout << "TCP layer: TCP header size is:" << tcp->header_size()<< "\n";

    //    raw = tcp->find_pdu<Tins::RawPDU>();
    //    if(raw) {
    //    std::cout << "RawPDU payload size:" << raw->payload_size() <<"\n";
    //    for (uint8_t b: raw->payload())
    //        std::cout << b;
    //    }
    //    std::cout<< "\n";
    //    std::cout<< "\n";
    //}

    //else if(udp) {
    //    std::cout << "UDP layer: UDP length:" << udp->length()
    //        <<" UDP header size is:" << udp->header_size()<< "\n"; 
    //    raw = udp->find_pdu<Tins::RawPDU>();
    //    if(raw) {
    //    std::cout << "RawPDU payload size:" << raw->payload_size() <<"\n";
    //    for (uint8_t b: raw->payload())
    //        std::cout << b;
    //    }
    //    std::cout<< "\n";
    //    std::cout<< "\n";
    //}

    //else {
    //    //raw pdu if any
    //    raw = pdu.find_pdu<Tins::RawPDU>();
    //    if(raw) {
    //    std::cout << "RawPDU payload size:" << raw->payload_size() <<"\n";
    //    for (uint8_t b: raw->payload())
    //        std::cout << b;
    //    }
    //    std::cout<< "\n";
    //    std::cout<< "\n";
    //} 
    ///////////////////////////////////////
    //base function structure for calc metadata
    ///////////////////////////////////////
    //std::cout<<"Packet number:" << pktcnt <<"\n";
//    if(eth) {
//        std::string protof = "eth";
//
//        std::cout << "Ethernet layer: Ethernet header size is:" << eth->header_size()
//            <<" Ethernet trailer size is:" << eth->trailer_size() << "\n"; 
//
//        //  if there is no ip layer
//        if(!ip && !ipv6) {
//            //determine eth payload type
//            //calc payload len 
//            std::cout <<"ARP";
//            raw = pdu.find_pdu<Tins::RawPDU>();
//            if(raw) {
//                protof += "/payload";
//                uint32_t sz = raw->payload_size();
//                uint32_t sz2 = eth->header_size();
//                uint32_t sz3 = eth->trailer_size();
//                std::cout << "Payload size is:" << sz << "\n";
//
//
//                std::cout <<"Total packet length is:"
////                    << eth->header_size() + eth->trailer_size() + sz << "\n";
//                        <<sz+sz2+sz3 <<"\n";
//                std::cout << "Proto string is: " << protof << "\n";
//                //get payload
//                std::vector<uint8_t> bytes = raw->payload();
//
//                std::ostringstream oss;
//                oss << std::hex << std::setfill('0');
//                std::for_each(
//                        bytes.cbegin(),
//                        bytes.cend(),
//                        [&](int c) { oss << std::setw(2) << c << ":"; }
//                        );
//                std::string hex_payload = oss.str();
//                hex_payload.pop_back();
//                std::cout << "Payload is:\n" << hex_payload;
//                std::cout <<"\n\n";
//
//            } else {
//            std::cout <<"Total packet length is:"
//                << eth->header_size() + eth->trailer_size();
//            std::cout << "Proto string is: " << protof << "\n";
//            std::cout <<"\n\n";
//            }
//        }
//
//        if(ip) {
//            //calc len as above, u know where
//            std::cout << "Total packet length is:"
//                << ip->tot_len() + eth->header_size() + eth->trailer_size() << "\n";
//            std::cout << "IP layer: IP length is:" << ip->tot_len()<< "\n";
//            protof += "/ip";
//
//            if(!tcp && !udp){
//                std::cout <<"ICMP";
//                raw = pdu.find_pdu<Tins::RawPDU>();
//                if(raw) {
//                    protof += "/payload";
//                    uint32_t sz = raw->payload_size();
//                    std::cout << "Payload size is:" << sz << "\n";
//                std::cout << "Proto string is: " << protof << "\n";
//                //get payload
//                std::vector<uint8_t> bytes = raw->payload();
//
//                std::ostringstream oss;
//                oss << std::hex << std::setfill('0');
//                std::for_each(
//                        bytes.cbegin(),
//                        bytes.cend(),
//                        [&](int c) { oss << std::setw(2) << c << ":"; }
//                        );
//                std::string hex_payload = oss.str();
//                hex_payload.pop_back();
//                std::cout << "Payload is:\n" << hex_payload;
//                } else
//                std::cout << "Proto string is: " << protof << "\n";
//                std::cout <<"\n\n";
//            }
//        }
//
//        if(ipv6) {
//            //calc len as above u know where
//            std::cout << "Total packet length is:" 
//                << 40 + ipv6->payload_length() + eth->header_size() + eth->trailer_size() << "\n";
//            std::cout << "IPv6 layer: IPv6 payload length:" << ipv6->payload_length()
//                << " IPv6 header size:" << ipv6->header_size() << "\n";
//            protof += "/ipv6";
//
//            if(!tcp && !udp) {
//                std::cout <<"ICMP";
//                raw = pdu.find_pdu<Tins::RawPDU>();
//                if(raw) {
//                    protof += "/payload";
//                    uint32_t sz = raw->payload_size();
//                    std::cout << "Payload size is:" << sz << "\n";
//                std::cout << "Proto string is: " << protof << "\n";
//                //get payload
//                std::vector<uint8_t> bytes = raw->payload();
//
//                std::ostringstream oss;
//                oss << std::hex << std::setfill('0');
//                std::for_each(
//                        bytes.cbegin(),
//                        bytes.cend(),
//                        [&](int c) { oss << std::setw(2) << c << ":"; }
//                        );
//                std::string hex_payload = oss.str();
//                hex_payload.pop_back();
//                std::cout << "Payload is:\n" << hex_payload;
//                } else
//                std::cout << "Proto string is: " << protof << "\n";
//                std::cout <<"\n\n";
//            }
//        }
//
//        if(tcp) {
//            protof += "/tcp";
//            std::cout << "TCP layer: TCP header size is:" << tcp->header_size()<< "\n";
//
//            raw = tcp->find_pdu<Tins::RawPDU>();
//            if(raw) {
//                std::cout << "RawPDU payload size:" << raw->payload_size() <<"\n";
//                protof += "/payload";
//                std::cout << "Proto string is: " << protof << "\n";
//                //get payload
//                std::vector<uint8_t> bytes = raw->payload();
//
//                std::ostringstream oss;
//                oss << std::hex << std::setfill('0');
//                std::for_each(
//                        bytes.cbegin(),
//                        bytes.cend(),
//                        [&](int c) { oss << std::setw(2) << c << ":"; }
//                        );
//                std::string hex_payload = oss.str();
//                hex_payload.pop_back();
//                std::cout << "Payload is:\n" << hex_payload;
//            } else {
//                std::cout << "Proto string is: " << protof << "\n";
//            }
//            std::cout <<"\n\n";
//
//            //get raw pdu
//            //process raw pdu if known to see what protocol it is 
//        }
//
//        if(udp) {
//            protof += "/udp";
//            std::cout << "UDP layer: UDP length:" << udp->length()
//                <<" UDP header size is:" << udp->header_size()<< "\n"; 
//            raw = udp->find_pdu<Tins::RawPDU>();
//            if(raw) {
//                std::cout << "RawPDU payload size:" << raw->payload_size() <<"\n";
//                protof += "/payload";
//                std::cout << "Proto string is: " << protof << "\n";
//
//                //get payload
//                std::vector<uint8_t> bytes = raw->payload();
//
//                std::ostringstream oss;
//                oss << std::hex << std::setfill('0');
//                std::for_each(
//                        bytes.cbegin(),
//                        bytes.cend(),
//                        [&](int c) { oss << std::setw(2) << c << ":"; }
//                        );
//                std::string hex_payload = oss.str();
//                hex_payload.pop_back();
//                std::cout << "Payload is:\n" << hex_payload;
//            } else {
//                std::cout << "Proto string is: " << protof << "\n";
//            }
//            std::cout <<"\n\n";
//        }
//    }
