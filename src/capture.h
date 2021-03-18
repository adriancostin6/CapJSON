#ifndef CAPTURE_H
#define CAPTURE_H
#include <memory>
#include <string>

#include <tins/tins.h>


class Capture{
    public:
        Capture(const std::string& filename);
        void run_sniffer(Tins::Sniffer& sniffer);

    private:
        std::unique_ptr<Tins::PacketWriter> p_writer;

        bool callback(const Tins::PDU& pdu);
};

#endif
