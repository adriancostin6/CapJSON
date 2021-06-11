#include <iostream>
#include <string>

#include "capture.h"

int main(int argc, char *argv[])
{

    if (argc < 2 || argc > 3) {
        std::cout << "Usage: # ./cap-json output_file_path [options]\n"
            << "  options:\n"
            << "    pcap    Generate pcap output files in the out directory\n"
            << "example: # ./cap-json /logs\n"
            << "description: Captures networks traffic and generates output"
            << "files in JSON format.\n"
            << "note: Needs to be run as root.\n";
        return -1;
    }

    std::string dir_path(argv[1]);
    bool gen_pcap = false;

    if(argc == 3) {
        std::string pcap_parameter(argv[2]);
        if (pcap_parameter.compare("pcap") == 0)
            gen_pcap = true;
    }
    
    Tins::NetworkInterface iface = 
        Tins::NetworkInterface::default_interface();
    Tins::NetworkInterface::Info info = iface.addresses();

    std::cout<< "Network interface: "<< iface.name()
        <<" IP ADDR: "<< info.ip_addr<< "\n";

    CapJSON::PacketCapture c(dir_path, gen_pcap);

    //sniffer configuration
    Tins::SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_immediate_mode(true);
    try {
        Tins::Sniffer sniffer(iface.name(),config);

        //capture the packets
        c.RunSniffer(sniffer);
    } 
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}
