#ifndef CAPJSON_NETWORK_PACKET_H
#define CAPJSON_NETWORK_PACKET_H

#include <tins/tins.h>

namespace CapJSON
{

struct NetworkPacket
{
    NetworkPacket(Tins::PDU& pdu);

    Tins::EthernetII* eth_;
    Tins::IP* ip_;
    Tins::IPv6* ipv6_;
    Tins::UDP* udp_;
    Tins::TCP* tcp_;
    Tins::RawPDU* raw_;
};

}
#endif // CAPJSON_NETWORK_PACKET_H
