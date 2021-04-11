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
    udp_(pdu.find_pdu<Tins::UDP>())
{
    if(eth_) {
        if(!ip_ && !ipv6_)
            arp_ = pdu.find_pdu<Tins::ARP>();

        if(ip_)
            if(!tcp_ && !udp_)
                icmp_ = pdu.find_pdu<Tins::ICMP>();

        if(ipv6_)
            if(!tcp_ && !udp_)
                icmpv6_ = pdu.find_pdu<Tins::ICMPv6>();
        if(tcp_)
            raw_ = tcp_->find_pdu<Tins::RawPDU>();

        if(udp_)
            raw_ = udp_->find_pdu<Tins::RawPDU>();
    }
}
}
