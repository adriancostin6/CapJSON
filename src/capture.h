#ifndef CAPJSON_CAPTURE_H
#define CAPJSON_CAPTURE_H

#include <memory>
#include <string>

#include <tins/tins.h>

#include "json.h"

namespace CapJSON
{

class PacketCapture
{
    public:
        PacketCapture();
        void RunSniffer(Tins::Sniffer& sniffer);

    private:
        bool Callback(Tins::PDU& pdu);
        void WriteToFile();
        void SetInitialTimestamp(const Tins::Timestamp& ts);

        std::vector<JSON> json_objects_;
        Tins::Timestamp initial_timestamp_;

        // ensures 100 packets per output file
        uint8_t output_count_;
        const int max_packets_ = 99;

        // counter for the number of packets
        uint32_t packet_count_;

        std::unique_ptr<Tins::PacketWriter> p_writer;

};

}
#endif //CAPJSON_CAPTURE_H
