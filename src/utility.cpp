#include "utility.h"

#include <iomanip>
#include <iostream>

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
    AddObject_Network(np, writer);
    AddObject_Transport(np, writer);
    AddObject_Payload(np,writer);

    //layers
    writer.EndObject();

    //timestamp
    writer.EndObject();
}

void AddObject_DataLink(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.Key("eth");
    writer.StartObject();

    writer.Key("eth_eth_dst");
    writer.String(np.eth_->src_addr().to_string().c_str());

    writer.Key("eth_eth_src");
    writer.String(np.eth_->dst_addr().to_string().c_str());

    writer.Key("eth_eth_type");
    writer.Uint(np.eth_->payload_type());

//    writer.Key("eth_eth_header_size");
//    writer.Uint(np.eth_->header_size());
//
//    writer.Key("eth_eth_trailer_size");
//    writer.Uint(np.eth_->trailer_size());

    //writer.EndObject();
}

void AddObject_Network(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    if(np.ip_) {
        //maybe we need to account for ipv6
        writer.Key("ip");
        writer.StartObject();

        writer.Key("ip_ip_version");
        writer.Uint(np.ip_->version());
        writer.Key("ip_ip_hdr_len");
        writer.Uint(np.ip_->head_len());
        writer.Key("ip_ip_tos");
        writer.Uint(np.ip_->tos());
        writer.Key("ip_ip_len");
        writer.Uint(np.ip_->tot_len());
        writer.Key("ip_ip_id");
        writer.Uint(np.ip_->id());

        //flags here
        uint8_t flags = np.ip_->flags();
        //could try converting back to big endian and showing as hex value
        //to emulate wireshark entirely but donno
        writer.Key("ip_ip_flags");
        writer.Uint(flags);

        //bit 0 is mf, bit 1 is df, bit 2 is rb
        writer.Key("ip_ip_flags_rb");
        writer.Uint((flags >> 2) & 1);
        writer.Key("ip_ip_flags_df");
        writer.Uint((flags >> 1) & 1);
        writer.Key("ip_ip_flags_mf");
        writer.Uint(flags & 1);

        writer.Key("ip_ip_frag_offset");
        writer.Uint(np.ip_->fragment_offset());
        writer.Key("ip_ip_ttl");
        writer.Uint(np.ip_->ttl());
        writer.Key("ip_ip_proto");
        writer.Uint(np.ip_->protocol());
        writer.Key("ip_ip_checksum");
        writer.Uint(np.ip_->checksum());
        writer.Key("ip_ip_src");
        writer.String(np.ip_->src_addr().to_string().c_str());
        writer.Key("ip_ip_dst");
        writer.String(np.ip_->dst_addr().to_string().c_str());

        //options here

        //padding?

        //writer.EndObject();
    }

    if(np.ipv6_) {
        //ipv6
        writer.Key("ipv6");
        writer.StartObject();

        writer.Key("ipv6_ipv6_version");
        writer.Uint(np.ipv6_->version());
        writer.Key("ipv6_ipv6_tclass");
        writer.Uint(np.ipv6_->traffic_class());
        writer.Key("ipv6_ipv6_flow");
        writer.Uint(np.ipv6_->flow_label());
        writer.Key("ipv6_ipv6_plen");
        writer.Uint(np.ipv6_->payload_length());
        writer.Key("ipv6_ipv6_nxt");
        writer.Uint(np.ipv6_->next_header());
        writer.Key("ipv6_ipv6_hlim");
        writer.Uint(np.ipv6_->hop_limit());
        writer.Key("ipv6_ipv6_src");
        writer.String(np.ipv6_->src_addr().to_string().c_str());
        writer.Key("ipv6_ipv6_dst");
        writer.String(np.ipv6_->dst_addr().to_string().c_str());

        //extensions ??

        //writer.EndObject();
    }
}

void AddObject_Transport(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    if(np.tcp_) {
        writer.Key("tcp");

        writer.StartObject();

        writer.Key("tcp_tcp_srcport");
        writer.Uint(np.tcp_->sport());

        writer.Key("tcp_tcp_dstport");
        writer.Uint(np.tcp_->dport());

        writer.Key("tcp_tcp_seq");
        writer.Uint(np.tcp_->seq());

        writer.Key("tcp_tcp_ack");
        writer.Uint(np.tcp_->ack_seq());

        writer.Key("tcp_tcp_data_offset");
        writer.Uint(np.tcp_->data_offset());

        //flags
        writer.Key("tcp_tcp_flags");
        writer.Uint(np.tcp_->flags());
        writer.Key("tcp_tcp_flags_cwr");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::CWR));
        writer.Key("tcp_tcp_flags_ece");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::ECE));
        writer.Key("tcp_tcp_flags_urg");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::URG));
        writer.Key("tcp_tcp_flags_ack");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::ACK));
        writer.Key("tcp_tcp_flags_psh");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::PSH));
        writer.Key("tcp_tcp_flags_rst");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::RST));
        writer.Key("tcp_tcp_flags_syn");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::SYN));
        writer.Key("tcp_tcp_flags_fin");
        writer.Uint(np.tcp_->get_flag(Tins::TCP::FIN));

        writer.Key("tcp_tcp_window_size");
        writer.Uint(np.tcp_->window());
        writer.Key("tcp_tcp_checksum");
        writer.Uint(np.tcp_->checksum());
        writer.Key("tcp_tcp_urgent_pointer");
        writer.Uint(np.tcp_->urg_ptr());

        //options

        //writer.EndObject();
    }

    if(np.udp_) {
        writer.Key("udp");
        writer.StartObject();

        writer.Key("udp_udp_srcport");
        writer.Uint(np.udp_->sport());
        writer.Key("udp_udp_dstport");
        writer.Uint(np.udp_->dport());
        writer.Key("udp_udp_length");
        writer.Uint(np.udp_->length());
        writer.Key("udp_udp_checksum");
        writer.Uint(np.udp_->checksum());

        //writer.EndObject();
    }
}

void AddTimestamp(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.Key("timestamp");
    
    // get microsecond timestamp and convert it to ms
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
                protocols += ":arp";
                frame_length += np.arp_->header_size();
            } 
            //if its not arp  ????
            //else {
            //    std::cout <<"Total packet length is:"
            //        << eth->header_size() + eth->trailer_size();
            //    std::cout << "Proto string is: " << protocols << "\n";
            //    std::cout <<"\n\n";
            //}
        }

        if(np.ip_) {
            //calc len as above, u know where
            protocols += ":ip";
            frame_length += np.ip_->tot_len();

            if(!np.tcp_ && !np.udp_)
                if(np.icmp_)
                    protocols += ":icmp";
        }

        if(np.ipv6_) {
            protocols += ":ipv6";
            frame_length += 40 + np.ipv6_->payload_length();

            if(!np.tcp_ && !np.udp_)
                if(np.icmpv6_) {
                    protocols += ":icmpv6";
                }
        }

        if(np.tcp_) {
            protocols += ":tcp";

            if(np.dns_)
                protocols += ":dns";
            else if(np.raw_)
                protocols += ":payload";
        }

        if(np.udp_) {
            protocols += ":udp";

            if(np.dhcp_)
                protocols += ":dhcp";
            else if(np.dhcpv6_)
                protocols += ":dhcpv6";
            else if(np.dns_)
                protocols += ":dns";
            else if(np.raw_)
                protocols += ":payload";
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
    if(np.eth_) {
        //  if there is no ip layer
        if(!np.ip_ && !np.ipv6_) {
            if(np.arp_) {
                //HWAddress<6> -> to string
                //IPv4Address
                writer.Key("arp");
                writer.StartObject();

                writer.Key("arp_arp_hw_addr_format");
                writer.Uint(np.arp_->hw_addr_format());
                writer.Key("arp_arp_prot_addr_format");
                writer.Uint(np.arp_->prot_addr_format());

                writer.Key("arp_arp_hw_addr_length");
                writer.Uint(np.arp_->hw_addr_length());
                writer.Key("arp_arp_prot_addr_length");
                writer.Uint(np.arp_->prot_addr_length());

                writer.Key("arp_arp_opcode");
                writer.Uint(np.arp_->opcode());

                writer.Key("arp_arp_sender_hw_addr");
                writer.String(np.arp_->sender_hw_addr().to_string().c_str());

                writer.Key("arp_arp_sender_ip_addr");
                writer.String(np.arp_->sender_ip_addr().to_string().c_str());

                writer.Key("arp_arp_target_hw_addr");
                writer.String(np.arp_->sender_hw_addr().to_string().c_str());

                writer.Key("arp_arp_target_ip_addr");
                writer.String(np.arp_->target_ip_addr().to_string().c_str());

                //arp
                writer.EndObject();
                return;
            }
//
//            //if(np.raw_) {
//            //    //get payload
//            //    std::vector<uint8_t> bytes = raw->payload();
//
//            //    std::ostringstream oss;
//            //    oss << std::hex << std::setfill('0');
//            //    std::for_each(
//            //            bytes.cbegin(),
//            //            bytes.cend(),
//            //            [&](int c) { oss << std::setw(2) << c << ":"; }
//            //            );
//            //    std::string hex_payload = oss.str();
//            //    hex_payload.pop_back();
//
//            //    writer.Key("eth_eth_payload");
//            //    writer.String(hex_payload.c_str());
//            //}


            //ethernet
            writer.EndObject();
            return;
        }

        if(np.ip_) {
            if(!np.tcp_ && !np.udp_){
                if(np.icmp_) {
                    writer.Key("icmp");
                    writer.StartObject();

                    writer.Key("icmp_icmp_type");
                    writer.Uint(np.icmp_->type());
                    writer.Key("icmp_icmp_code");
                    writer.Uint(np.icmp_->code());
                    writer.Key("icmp_icmp_checksum");
                    writer.Uint(np.icmp_->checksum());

                    //data here 


                    writer.EndObject();
                    return;
                }

//                //if(np.raw_) {
//                //    //get payload
//                //    std::vector<uint8_t> bytes = raw->payload();
//
//                //    std::ostringstream oss;
//                //    oss << std::hex << std::setfill('0');
//                //    std::for_each(
//                //            bytes.cbegin(),
//                //            bytes.cend(),
//                //            [&](int c) { oss << std::setw(2) << c << ":"; }
//                //            );
//                //    std::string hex_payload = oss.str();
//                //    hex_payload.pop_back();
//
//                //    writer.Key("ip_ip_payload");
//                //    writer.String(hex_payload.c_str());
//                //}

                //ip
                writer.EndObject();
                return;
            }
        }
//
        if(np.ipv6_) {
            if(!np.tcp_ && !np.udp_) {
                if(np.icmpv6_) {
                    writer.Key("icmpv6");
                    writer.StartObject();

                    writer.Key("icmpv6_icmpv6_type");
                    writer.Uint(np.icmpv6_->type());
                    writer.Key("icmpv6_icmpv6_code");
                    writer.Uint(np.icmpv6_->code());
                    writer.Key("icmpv6_icmpv6_checksum");
                    writer.Uint(np.icmpv6_->checksum());

                    //data here

                    writer.EndObject();
                    return;
                }
//
//                //if(np.raw_) {
//                //    //get payload
//                //    std::vector<uint8_t> bytes = raw->payload();
//
//                //    std::ostringstream oss;
//                //    oss << std::hex << std::setfill('0');
//                //    std::for_each(
//                //            bytes.cbegin(),
//                //            bytes.cend(),
//                //            [&](int c) { oss << std::setw(2) << c << ":"; }
//                //            );
//                //    std::string hex_payload = oss.str();
//                //    hex_payload.pop_back();
//                //    
//                //    writer.Key("ipv6_ipv6_payload");
//                //    writer.String(hex_payload.c_str());
//                //}
//
                //ipv6
                writer.EndObject();
                return;
            }
        }

        if(np.tcp_) {
            if(np.raw_) {
                //get payload
                std::vector<uint8_t> bytes = np.raw_->payload();

                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                std::for_each(
                        bytes.cbegin(),
                        bytes.cend(),
                        [&](int c) { oss << std::setw(2) << c << ":"; }
                        );
                std::string hex_payload = oss.str();
                hex_payload.pop_back();

                writer.Key("tcp_tcp_payload");
                writer.String(hex_payload.c_str());

                if(np.dns_) {

                    writer.Key("dns");
                    writer.StartObject();

                    writer.Key("dns_dns_id");
                    writer.Uint(np.dns_->id());
                    writer.Key("dns_dns_qr");
                    writer.Uint(np.dns_->type());
                    writer.Key("dns_dns_opcode");
                    writer.Uint(np.dns_->opcode());
                    writer.Key("dns_dns_aa");
                    writer.Uint(np.dns_->authoritative_answer());
                    writer.Key("dns_dns_tc");
                    writer.Uint(np.dns_->truncated());
                    writer.Key("dns_dns_rd");
                    writer.Uint(np.dns_->recursion_desired());
                    writer.Key("dns_dns_ra");
                    writer.Uint(np.dns_->recursion_available());
                    writer.Key("dns_dns_z");
                    writer.Uint(np.dns_->z());
                    writer.Key("dns_dns_ad");
                    writer.Uint(np.dns_->authenticated_data());
                    writer.Key("dns_dns_cd");
                    writer.Uint(np.dns_->checking_disabled());
                    writer.Key("dns_dns_rcode");
                    writer.Uint(np.dns_->rcode());
                    writer.Key("dns_dns_qcount");
                    writer.Uint(np.dns_->questions_count());
                    writer.Key("dns_dns_anscount");
                    writer.Uint(np.dns_->answers_count());
                    writer.Key("dns_dns_authcount");
                    writer.Uint(np.dns_->authority_count());
                    writer.Key("dns_dns_additcount");
                    writer.Uint(np.dns_->additional_count());

                    writer.EndObject();
                }

            }

            //tcp
            writer.EndObject();
            return;
        }

        if(np.udp_) {
            if(np.raw_) {
                //get payload
                std::vector<uint8_t> bytes = np.raw_->payload();

                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                std::for_each(
                        bytes.cbegin(),
                        bytes.cend(),
                        [&](int c) { oss << std::setw(2) << c << ":"; }
                        );
                std::string hex_payload = oss.str();
                hex_payload.pop_back();

                writer.Key("udp_udp_payload");
                writer.String(hex_payload.c_str());

                if(np.dns_) {
                    writer.Key("dns");
                    writer.StartObject();

                    writer.Key("dns_dns_id");
                    writer.Uint(np.dns_->id());
                    writer.Key("dns_dns_qr");
                    writer.Uint(np.dns_->type());
                    writer.Key("dns_dns_opcode");
                    writer.Uint(np.dns_->opcode());
                    writer.Key("dns_dns_aa");
                    writer.Uint(np.dns_->authoritative_answer());
                    writer.Key("dns_dns_tc");
                    writer.Uint(np.dns_->truncated());
                    writer.Key("dns_dns_rd");
                    writer.Uint(np.dns_->recursion_desired());
                    writer.Key("dns_dns_ra");
                    writer.Uint(np.dns_->recursion_available());
                    writer.Key("dns_dns_z");
                    writer.Uint(np.dns_->z());
                    writer.Key("dns_dns_ad");
                    writer.Uint(np.dns_->authenticated_data());
                    writer.Key("dns_dns_cd");
                    writer.Uint(np.dns_->checking_disabled());
                    writer.Key("dns_dns_rcode");
                    writer.Uint(np.dns_->rcode());
                    writer.Key("dns_dns_qcount");
                    writer.Uint(np.dns_->questions_count());
                    writer.Key("dns_dns_anscount");
                    writer.Uint(np.dns_->answers_count());
                    writer.Key("dns_dns_authcount");
                    writer.Uint(np.dns_->authority_count());
                    writer.Key("dns_dns_additcount");
                    writer.Uint(np.dns_->additional_count());

                    writer.EndObject();
                }
                else if(np.dhcp_) {
                    writer.Key("dhcp");
                    writer.StartObject();

                    //figure out the type of message 

                    switch(np.dhcp_->type()) {
                        case 1:
                            std::cout << "discover message\n";
                            break;
                        case 2:
                            std::cout << "discover message\n";
                            break;
                        case 3:
                            std::cout << "offer message\n";
                            break;
                        case 4:
                            std::cout << "request message\n";
                            break;
                        case 5:
                            std::cout << "decline message\n";
                            break;
                        case 6:
                            std::cout << "ack message\n";
                            break;
                        case 7:
                            std::cout << "nak message\n";
                            break;
                        case 8:
                            std::cout << "inform message\n";
                            break;
                        }

                        writer.EndObject();
                }
                else if(np.dhcpv6_) {
                    writer.Key("dhcpv6");
                    writer.StartObject();

                    switch(np.dhcpv6_->msg_type()) {
                        case 1:
                            std::cout << "solicit message\n";
                            break;
                        case 2:
                            std::cout << "advertise message\n";
                            break;
                        case 3:
                            std::cout << "request message\n";
                            break;
                        case 4:
                            std::cout << "confirm message\n";
                            break;
                        case 5:
                            std::cout << "renew message\n";
                            break;
                        case 6:
                            std::cout << "rebind message\n";
                            break;
                        case 7:
                            std::cout << "reply message\n";
                            break;
                        case 8:
                            std::cout << "release message\n";
                            break;
                        case 9:
                            std::cout << "decline message\n";
                            break;
                        case 10:
                            std::cout << "reconfigure message\n";
                            break;
                        case 11:
                            std::cout << "info_request message\n";
                            break;
                        case 12:
                            std::cout << "relay_forward message\n";
                            break;
                        case 13:
                            std::cout << "relay_reply message\n";
                            break;
                        case 14:
                            std::cout << "lease_query message\n";
                            break;
                        case 15:
                            std::cout << "lease_query_reply message\n";
                            break;
                        case 16:
                            std::cout << "lease_query_done message\n";
                            break;
                        case 17:
                            std::cout << "lease_query_data message\n";
                            break;
                        }

                    writer.EndObject();
                }
            }

            //udp
            writer.EndObject();
            return;
        }
    }
}
}
