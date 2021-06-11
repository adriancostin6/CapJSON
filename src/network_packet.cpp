#include "network_packet.h"

namespace CapJSON
{
NetworkPacket::NetworkPacket(Tins::PDU& pdu, const Tins::Timestamp& ts, uint32_t pn) :
    ts_(ts),
    packet_number_(pn),
    eth_(pdu.find_pdu<Tins::EthernetII>()),
    ip_(pdu.find_pdu<Tins::IP>()),
    ipv6_(pdu.find_pdu<Tins::IPv6>()),
    tcp_(pdu.find_pdu<Tins::TCP>()),
    udp_(pdu.find_pdu<Tins::UDP>()),
    arp_(pdu.find_pdu<Tins::ARP>()),
    icmp_(pdu.find_pdu<Tins::ICMP>()),
    icmpv6_(pdu.find_pdu<Tins::ICMPv6>()),
    dns_(nullptr), dhcp_(nullptr), dhcpv6_(nullptr)
{
    if(eth_) {
        if(tcp_) {
            raw_ = tcp_->find_pdu<Tins::RawPDU>();
            if(raw_)
                //http
                //other app layer protocols
                //dns_ = raw_->to<Tins::DNS>().clone(); 
                Tins::DNS dns = raw_->to<Tins::DNS>();
                int a =5;
        }

        if(udp_) {
            raw_ = udp_->find_pdu<Tins::RawPDU>();
            if(raw_) {
                //trying to do this throws because what if the raw data 
                // is not dhcp
                Tins::DHCP dhcp = raw_->to<Tins::DHCP>();
                Tins::DNS dns = raw_->to<Tins::DNS>();
                //dhcp_ = raw_->to<Tins::DHCP>().clone(); 
                //dhcpv6_ = raw_->to<Tins::DHCPv6>().clone(); 
                int a =5;
            }
        }
    }
}

NetworkPacket::~NetworkPacket()
{
    //docs specify we have to delete these manually if we use the clone function
    if(dns_)
        delete dns_;
    if(dhcp_)
        delete dhcp_;
    if(dhcpv6_)
        delete dhcpv6_;
}
}
