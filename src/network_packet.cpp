#include "network_packet.h"

NetworkPacket::NetworkPacket(Tins::PDU& pdu) :
    eth_(pdu.find_pdu<Tins::EthernetII>()),
    ip_(pdu.find_pdu<Tins::IP>()),
    ipv6_(pdu.find_pdu<Tins::IPv6>()),
    tcp_(pdu.find_pdu<Tins::TCP>()),
    udp_(pdu.find_pdu<Tins::UDP>()),
    raw_(pdu.find_pdu<Tins::RawPDU>())
{}
