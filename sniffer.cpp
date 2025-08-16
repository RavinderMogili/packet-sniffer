#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>     // for iphdr
#include <netinet/tcp.h>    // for tcphdr
#include <sys/socket.h>
#include <sys/types.h>

int main() {
    // Create raw socket
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    std::cout << "Mini Packet Sniffer started... (press Ctrl+C to stop)" << std::endl;

    unsigned char *buffer = new unsigned char[65536];
    sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (true) {
        // Receive packet
        int data_size = recvfrom(sock_raw, buffer, 65536, 0,
                                 (struct sockaddr *)&src_addr, &addr_len);
        if (data_size < 0) {
            perror("Recvfrom error");
            break;
        }

        // Extract IP header
        struct iphdr *ip_header = (struct iphdr*)buffer;
        struct sockaddr_in src, dst;

        src.sin_addr.s_addr = ip_header->saddr;
        dst.sin_addr.s_addr = ip_header->daddr;

        std::cout << "Packet: "
                  << inet_ntoa(src.sin_addr) << " -> "
                  << inet_ntoa(dst.sin_addr)
                  << " | Protocol: " << (int)ip_header->protocol
                  << " | Size: " << data_size
                  << std::endl;
    }

    close(sock_raw);
    delete[] buffer;
    return 0;
}

