#include "utility.h"

#include "network_packet.h"

namespace CapJSON
{

void BuildJSON(NetworkPacket& np, Writer<StringBuffer>& writer)
{
    writer.StartObject();

    AddObject_DataLink(np, writer);

    if(np.ip_)
        AddObject_Network(np, writer, true);
    if(np.ipv6_)
        AddObject_Network(np, writer, false);

    if(np.tcp_)
        AddObject_Transport(np, writer, true);
    if(np.udp_)
        AddObject_Transport(np, writer, false);

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

}
