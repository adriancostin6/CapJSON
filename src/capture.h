#ifndef CAPJSON_CAPTURE_H
#define CAPJSON_CAPTURE_H

#include <memory>
#include <string>

#include <tins/tins.h>

namespace CapJSON
{

class Capture{
    public:
        Capture(const std::string& filename);
        void run_sniffer(Tins::Sniffer& sniffer);

    private:
        std::unique_ptr<Tins::PacketWriter> p_writer;

        bool callback(Tins::PDU& pdu);
};

}
#endif //CAPJSON_CAPTURE_H
