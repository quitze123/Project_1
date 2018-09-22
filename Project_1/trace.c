#include "smartalloc.h"
#include "checksum.h"
#include <stdint.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#define ETHERNET 14
#define DST_MAC 6
#define SRC_MAC 6
#define SENDER_MAC 6
#define SENDER_IP 4
#define TARGET_MAC 6
#define TARGET_IP 4
#define ARP 0x0806
#define REQUEST 0x0001
#define REPLY 0x0002

struct ethernet_header
{
   uint8_t dst_addr[DST_MAC];
   uint8_t src_addr[SRC_MAC];
   uint16_t type;

} __attribute__((packed));

struct arp_header
{
   uint16_t hardware_type;
   uint16_t protocol_type;
   uint8_t hardware_size;
   uint8_t protocol_size;
   uint16_t opcode;
   uint8_t sndr_mac[SENDER_MAC];
   uint8_t sndr_ip[SENDER_IP];
   uint8_t trgt_mac[TARGET_MAC];
   uint8_t trgt_ip[TARGET_IP];

} __attribute__((packed));

void usage(char * argv)
{
   printf("Usage : %s PCAP_FILE\n", argv);
   exit(EXIT_FAILURE);
}

pcap_t * open_file(char * f_name)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t * temp  = pcap_open_offline(f_name, errbuf);
   if(temp == NULL)
   {
      printf("%s\n", errbuf);
      exit(EXIT_FAILURE);
   }
   return temp;
}

void run(pcap_t * pcap_ptr);
uint16_t ethernet(const u_char * pkt_data);
void arp(const u_char * pkt_data);

int main(int argc, char ** argv)
{
   pcap_t * pcap_ptr = NULL;

   if(argc != 2)
   {
      usage(argv[0]);
   }

   pcap_ptr = open_file(argv[1]);

   run(pcap_ptr);

   pcap_close(pcap_ptr);
   return EXIT_SUCCESS;
}

void run(pcap_t * pcap_ptr)
{
   const u_char * pkt_data = NULL;
   struct pcap_pkthdr * pkt_header = NULL;
   
   uint32_t pkt_num = 0;
   uint16_t type = 0;

   while(pcap_next_ex(pcap_ptr, &pkt_header, &pkt_data) == 1)
   {
      pkt_num++;
      printf("Packet number: %d  Packet Len: %d\n", pkt_num, pkt_header->len);
      type = ethernet(pkt_data);

      if(type == ARP)
      {
         printf("\t\tType: ARP\n");
         arp(pkt_data);
      }
   }
}

uint16_t ethernet(const u_char * pkt_data)
{
   struct ethernet_header * eh = (struct ethernet_header *)pkt_data;
   
   printf("\n\tEthernet Header\n");
   printf("\t\tDest MAC: %s\n", ether_ntoa((struct ether_addr *)eh->dst_addr));
   printf("\t\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)eh->src_addr));
   
   return ntohs(eh->type);
}

void arp(const u_char * pkt_data)
{
   struct arp_header * ah = (struct arp_header *)(pkt_data 
      + sizeof(struct ethernet_header));
   
    
   printf("\n\tARP Header\n");
   printf("\t\tOpcode: ");
   if(ntohs(ah->opcode) == REPLY)
   {
      printf("Reply\n");
   }
   else if(ntohs(ah->opcode) == REQUEST)
   {
       printf("Request\n");
   }
   printf("\t\tSender MAC: %s\n", 
      ether_ntoa((struct ether_addr *)ah->sndr_mac));
   printf("\t\tSender IP: %s\n", 
      inet_ntoa(*((struct in_addr *)(ah->sndr_ip))));
   printf("\t\tTarget MAC: %s\n", 
      ether_ntoa((struct ether_addr *)ah->trgt_mac));
   printf("\t\tTarget IP: %s\n\n", 
      inet_ntoa(*((struct in_addr *)(ah->trgt_ip))));
}
