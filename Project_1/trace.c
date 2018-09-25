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
#define IP 0x0800
#define ICMP 0x01
#define UDP 0x11
#define TCP 0x06
#define ICMP_REQUEST 0x08
#define ICMP_REPLY 0x00
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

struct ip_header
{
   uint8_t version_header_length;/*version header length = 8 bits*/
   uint8_t ds_ecn; /*Differentiated Services Code Poin Explicit Congestion Notification = 8 bits*/
   uint16_t total_length; /*total length = 16 bits*/
   uint16_t identification;/*identification = 16 bits*/
   uint16_t flag_fragment_offset;/*flags = 3 bits fragment offset = 13 bits*/
   uint8_t time_to_live;/*time to live = 8 bits*/
   uint8_t protocol;
   uint16_t header_checksum;
   uint8_t source_ip[SENDER_IP];
   uint8_t destination_ip[TARGET_IP];

} __attribute__((packed));

struct icmp_header
{
   uint8_t type;
   uint8_t code;
   uint16_t checksum;
   uint32_t rest_of_header;
} __attribute__((packed));

struct tcp_header
{
   uint16_t source_port;
   uint16_t destination_port;
   uint32_t sequence_number;
   uint32_t ack_num;
   uint8_t data_offset_reserved_ns;
   uint8_t cwr_ece_urg_ack_psh_rst_syn_fin;
   uint16_t window_size;
   uint16_t check_sum;
   uint16_t urgent_ptr;

}

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
uint8_t ip(const u_char * pkt_data);
void icmp(const u_char * pkt_data);

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
   
   uint8_t protocol = -1;   

   while(pcap_next_ex(pcap_ptr, &pkt_header, &pkt_data) == 1)
   {
      pkt_num++;
      printf("\nPacket number: %d  Packet Len: %d\n", pkt_num, pkt_header->len);
      type = ethernet(pkt_data);
      
      printf("\t\tType: ");
      if(type == ARP)
      {
         printf("ARP\n");
         arp(pkt_data);
      }
      else if(type == IP)
      {
         printf("IP\n");
         protocol = ip(pkt_data);
      }
      else
      {
         printf("Unknown\n");
      }

      if(protocol == ICMP)
      {
         icmp(pkt_data);
         protocol = -1;
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
   printf("\t\tTarget IP: %s\n", 
      inet_ntoa(*((struct in_addr *)(ah->trgt_ip))));
}

uint8_t ip(const u_char * pkt_data)
{
   struct ip_header * iph = (struct ip_header *)(pkt_data
      + sizeof(struct ethernet_header));

   uint16_t * temp_ptr_iph = (uint16_t *)iph;

   uint8_t header_length = (iph->version_header_length & 0x0f) * 4;
   printf("\n\tIP Header\n");
   //printf("\t\tTOS: 0x%x\n", iph->ds_ecn >> 2);
   printf("\t\tTOS: 0x%x\n", iph->ds_ecn);
   printf("\t\tTTL: %d\n", iph->time_to_live);
   printf("\t\tProtocol: ");
   if(iph->protocol == ICMP)
   {
      printf("ICMP\n");
   }
   else if(iph->protocol == UDP)
   {
      printf("UDP\n");
   }
   else if(iph->protocol == TCP)
   {
      printf("TCP\n");
   }
   else
   {
      printf("Unknown\n");
   }
   printf("\t\tChecksum: ");
   if(in_cksum(temp_ptr_iph, header_length) == 0)
   {
      printf("Correct (0x%x)\n", ntohs(iph->header_checksum));
   }
   else
   {
      printf("Incorrect (0x%x)\n", ntohs(iph->header_checksum));
   }
   printf("\t\tSender IP: %s\n", 
      inet_ntoa(*((struct in_addr *)(iph->source_ip))));
   printf("\t\tDest IP: %s\n",
      inet_ntoa(*((struct in_addr *)(iph->destination_ip))));

   return iph->protocol;
}

void icmp(const u_char * pkt_data)
{
   struct ip_header * iph = (struct ip_header *)(pkt_data
      + sizeof(struct ethernet_header));
   uint8_t ip_header_length = (iph->version_header_length & 0x0f) * 4;

   struct icmp_header * ih = (struct icmp_header *)(pkt_data
      + sizeof(struct ethernet_header) + ip_header_length);

   printf("\n\tICMP Header\n");
   printf("\t\tType: ");
   if(ih->type == ICMP_REQUEST)
   {
      printf("Request\n");
   }
   else if(ih->type == ICMP_REPLY)
   {
      printf("Reply\n");
   }
   else
   {
      printf("Unknown\n");
   }
}
