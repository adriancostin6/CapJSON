#include <iostream>

#include "capture.h"

int main()
{
    Tins::NetworkInterface iface = 
        Tins::NetworkInterface::default_interface();
    Tins::NetworkInterface::Info info = iface.addresses();

    std::cout<< "Network interface: "<< iface.name()
        <<" IP ADDR: "<< info.ip_addr<< "\n";

    CapJSON::PacketCapture c;

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
