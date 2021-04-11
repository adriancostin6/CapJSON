#include "utility.h"

#include "network_packet.h"

namespace CapJSON
{
void BuildJSON(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.StartObject();

    AddTimestamp(np, writer);

    writer.Key("layers");
    writer.StartObject();

    AddObject_FrameMetadata(np, writer);

    //when adding layers
    // begin object
    //code goes here 
    // end object

    AddObject_DataLink(np, writer);

    if(np.ip_)
        AddObject_Network(np, writer, true);
    if(np.ipv6_)
        AddObject_Network(np, writer, false);

    if(np.tcp_)
        AddObject_Transport(np, writer, true);
    if(np.udp_)
        AddObject_Transport(np, writer, false);

    //layers
    writer.EndObject();

    //timestamp
    writer.EndObject();
}

void AddObject_DataLink(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.Key("eth");
    writer.StartObject();

    writer.Key("eth.dst");
    writer.String(np.eth_->src_addr().to_string().c_str());

    writer.Key("eth.src");
    writer.String(np.eth_->dst_addr().to_string().c_str());

    writer.Key("eth.type");
    writer.Uint(np.eth_->payload_type());

    writer.Key("eth.header_size");
    writer.Uint(np.eth_->header_size());

    writer.Key("eth.trailer_size");
    writer.Uint(np.eth_->trailer_size());

    writer.EndObject();
}

void AddObject_Network( NetworkPacket& np, Writer<StringBuffer>& writer, bool ipv4)
{
    if(ipv4) {
        //maybe we need to account for ipv6
        writer.Key("ip");
        writer.StartObject();

        writer.Key("ip.version");
        writer.Uint(np.ip_->version());

        writer.Key("ip.hdr_len");
        writer.Uint(np.ip_->head_len());

        writer.Key("ip.len");
        writer.Uint(np.ip_->tot_len());

        writer.Key("ip.id");
        writer.Uint(np.ip_->id());

        //flags here

        writer.Key("ip.frag_offset");
        writer.Uint(np.ip_->fragment_offset());

        writer.Key("ip.ttl");
        writer.Uint(np.ip_->ttl());

        writer.Key("ip.proto");
        writer.Uint(np.ip_->protocol());

        writer.Key("ip.checksum");
        writer.Uint(np.ip_->checksum());

        writer.Key("ip.tos");
        writer.Uint(np.ip_->tos());

        writer.Key("ip.src");
        writer.String(np.ip_->src_addr().to_string().c_str());

        writer.Key("ip.dst");
        writer.String(np.ip_->dst_addr().to_string().c_str());

        writer.EndObject();
        return;
    }

    //ipv6
    writer.Key("ipv6");
    writer.StartObject();

    writer.Key("ipv6.version");
    writer.Uint(np.ipv6_->version());

    writer.Key("ipv6.tclass");
    writer.Uint(np.ipv6_->traffic_class());

    writer.Key("ipv6.flow");
    writer.Uint(np.ipv6_->flow_label());

    writer.Key("ipv6.plen");
    writer.Uint(np.ipv6_->payload_length());

    writer.Key("ipv6.nxt");
    writer.Uint(np.ipv6_->next_header());

    writer.Key("ipv6.hlim");
    writer.Uint(np.ipv6_->hop_limit());

    writer.Key("ipv6.src");
    writer.String(np.ipv6_->src_addr().to_string().c_str());

    writer.Key("ipv6.dst");
    writer.String(np.ipv6_->dst_addr().to_string().c_str());

    writer.EndObject();
}

void AddObject_Transport(NetworkPacket& np, Writer<StringBuffer>& writer, bool tcp)
{
    if(tcp) {
        writer.Key("tcp");

        writer.StartObject();

        writer.Key("tcp.srcport");
        writer.Uint(np.tcp_->sport());
        writer.Key("tcp.dstport");
        writer.Uint(np.tcp_->dport());
        writer.Key("tcp.seq");
        writer.Uint(np.tcp_->seq());
        writer.Key("tcp.ack");
        writer.Uint(np.tcp_->ack_seq());
        //writer.Key("tcp.hdr_len"); //?? is the header len neede?
        //flags

        //options

        writer.Key("tcp.window_size");
        writer.Uint(np.tcp_->window());
        writer.Key("tcp.checksum");
        writer.Uint(np.tcp_->checksum());
        writer.Key("tcp.urgent_pointer");
        writer.Uint(np.tcp_->urg_ptr());
        writer.Key("tcp.data_offset");
        writer.Uint(np.tcp_->data_offset());

        writer.EndObject();

        return;
    }

    writer.Key("udp");

    writer.StartObject();

    writer.Key("udp.srcport");
    writer.Uint(np.udp_->sport());
    writer.Key("udp.dstport");
    writer.Uint(np.udp_->dport());
    writer.Key("udp.length");
    writer.Uint(np.udp_->length());
    writer.Key("udp.checksum");
    writer.Uint(np.udp_->checksum());

    writer.EndObject();
}

void AddTimestamp(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.Key("timestamp");
    
    // get microsecond timestamp and convert it to ms
    //pray this works
    std::chrono::microseconds us = np.ts_;
    us /= 1000  ;

    // cast timestamp to c_str and pass it to rapidjson write function
    std::string mili = std::to_string(us.count());
    writer.String(mili.c_str());
}

void AddObject_FrameMetadata(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.Key("frame");
    writer.StartObject();

    Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();

    writer.Key("frame_frame_interface_id");
    writer.Uint(iface.id());
    writer.Key("frame_frame_interface_name");
    writer.String(iface.name().c_str());

    //time in standard time
    std::chrono::microseconds us = np.ts_;
    us /= 1000;
    
    std::string mili = std::to_string(us.count());
    writer.Key("frame_frame_time_epoch");
    writer.String(mili.c_str());

    //frame number
    uint32_t frame_number = np.packet_number_;
    writer.Key("frame_frame_number");
    writer.Uint(frame_number);

    //frame length
    //frame protof
    uint32_t frame_length = 0;
    std::string protocols = "";
    if(np.eth_) {
        protocols += "eth";

        frame_length += np.eth_->header_size() + np.eth_->trailer_size();

        //  if there is no ip layer
        if(!np.ip_ && !np.ipv6_) {
            if(np.arp_) {
                protocols += "/arp";
                frame_length += np.arp_->header_size();
            } 
            //if its not arp 
            //else {
            //    std::cout <<"Total packet length is:"
            //        << eth->header_size() + eth->trailer_size();
            //    std::cout << "Proto string is: " << protocols << "\n";
            //    std::cout <<"\n\n";
            //}
        }

        if(np.ip_) {
            //calc len as above, u know where
            protocols += "/ip";
            frame_length += np.ip_->tot_len();

            if(!np.tcp_ && !np.udp_)
                if(np.icmp_)
                    protocols += "/icmp";
        }

        if(np.ipv6_) {
            protocols += "/ipv6";
            frame_length += 40 + np.ipv6_->payload_length();

            if(!np.tcp_ && !np.udp_)
                if(np.icmpv6_) {
                    protocols += "/icmpv6";
                }
        }

        if(np.tcp_) {
            protocols += "/tcp";

            if(np.raw_)
                protocols += "/payload";
        }

        if(np.udp_) {
            protocols += "/udp";
            if(np.raw_)
                protocols += "/payload";
        }
    }

    writer.Key("frame_frame_length");
    writer.Uint(frame_length);
    writer.Key("frame_frame_protocols");
    writer.String(protocols.c_str());

    writer.EndObject();
}

void AddObject_Payload(NetworkPacket& np, Writer<StringBuffer>& writer)
{
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
//                    //                    << eth->header_size() + eth->trailer_size() + sz << "\n";
//                    <<sz+sz2+sz3 <<"\n";
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
//                std::cout <<"Total packet length is:"
//                    << eth->header_size() + eth->trailer_size();
//                std::cout << "Proto string is: " << protof << "\n";
//                std::cout <<"\n\n";
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
//                    std::cout << "Proto string is: " << protof << "\n";
//                    //get payload
//                    std::vector<uint8_t> bytes = raw->payload();
//
//                    std::ostringstream oss;
//                    oss << std::hex << std::setfill('0');
//                    std::for_each(
//                            bytes.cbegin(),
//                            bytes.cend(),
//                            [&](int c) { oss << std::setw(2) << c << ":"; }
//                            );
//                    std::string hex_payload = oss.str();
//                    hex_payload.pop_back();
//                    std::cout << "Payload is:\n" << hex_payload;
//                } else
//                    std::cout << "Proto string is: " << protof << "\n";
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
//                    std::cout << "Proto string is: " << protof << "\n";
//                    //get payload
//                    std::vector<uint8_t> bytes = raw->payload();
//
//                    std::ostringstream oss;
//                    oss << std::hex << std::setfill('0');
//                    std::for_each(
//                            bytes.cbegin(),
//                            bytes.cend(),
//                            [&](int c) { oss << std::setw(2) << c << ":"; }
//                            );
//                    std::string hex_payload = oss.str();
//                    hex_payload.pop_back();
//                    std::cout << "Payload is:\n" << hex_payload;
//                } else
//                    std::cout << "Proto string is: " << protof << "\n";
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
//
//
}
}
