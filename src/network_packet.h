#ifndef CAPJSON_NETWORK_PACKET_H
#define CAPJSON_NETWORK_PACKET_H

#include <tins/tins.h>

namespace CapJSON
{

struct NetworkPacket
{
    NetworkPacket(Tins::PDU& pdu, const Tins::Timestamp& ts, uint32_t pn);

    const Tins::Timestamp ts_;
    uint32_t packet_number_;
    Tins::EthernetII* eth_;
    Tins::IP* ip_;
    Tins::IPv6* ipv6_;
    Tins::UDP* udp_;
    Tins::TCP* tcp_;
    Tins::ARP* arp_;
    Tins::ICMP* icmp_;
    Tins::ICMPv6* icmpv6_;
    Tins::RawPDU* raw_;
};

}
#endif // CAPJSON_NETWORK_PACKET_H
