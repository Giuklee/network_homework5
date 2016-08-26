#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#include <stdio.h>
#include "pcap.h"
#include <stdint.h>
#pragma comment (lib, "wpcap.lib")  

int SetCheckSum(unsigned char*, struct pcap_pkthdr*);
u_short ip_sum_calc(u_short, u_short *);
//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

//Ip header (v4)
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	UINT8 ip_total_length[2]; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;
// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	UINT8 sequence[4] ; // sequence number - 32 bits
	UINT8 acknowledge[4]; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

						   ////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;


ETHER_HDR *ethhdr, *ethhdr2;
IPV4_HDR *iphdr, *iphdr2;
TCP_HDR *tcphdr, *tcphdr2;
unsigned char *data, *data2;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *fp;
	int inum;
	int i = 0,j=0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	unsigned char packet_s[9999] = { 0, };
	unsigned char packet_c[9999] = { 0, };
	static const char get_str[] = "GET /";
	time_t local_tv_sec;
	unsigned short checksum_s, checksum_c;
	int sequence_s;
	int header_len_s, header_len_c;


	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPCap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	if ((adhandle = pcap_open(d->name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);
	//Ethernet header
	ethhdr = (ETHER_HDR *)packet_s;
	ethhdr2 = (ETHER_HDR *)packet_c;
	//ip header
	iphdr = (IPV4_HDR *)(packet_s + sizeof(ETHER_HDR));
	iphdr2 = (IPV4_HDR *)(packet_c + sizeof(ETHER_HDR));
	//tcp header
	tcphdr = (TCP_HDR *)(packet_s + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));
	tcphdr2 = (TCP_HDR *)(packet_c + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));
	while ((res = pcap_next_ex(adhandle, &header, (const unsigned char **)&pkt_data)) >= 0) {
		if (res == 0)
			continue;
		///////////////////////////////////////
		// eth + ip + tcp = 54 bytes
		if (strncmp(pkt_data+54, get_str, sizeof(get_str) - 1) == 0) { // find "GET /"
			printf("==================================\n");
			// send "blocked" message to server
		//	printf("### %d ###\n",header->len);
			memcpy(packet_s, pkt_data, 54);
		//	memcpy(packet_c, pkt_data, 54);
			for (i = 0; i < 54; i++) {
				printf("%x ", packet_s[i]);
			}
			printf("##tcp sport : %d\n", tcphdr->source_port);
			printf("##tcp dport : %d\n", tcphdr->dest_port);
			memcpy(packet_s + 54, "blocked\n\n\n", strlen("blocked\n\n\n"));
		//	memcpy(packet_c + 54, "blocked\n\n\n", strlen("blocked\n\n\n"));

			tcphdr->rst = 1;
			//tcphdr->ack = 0;
			//tcphdr->syn = 1;
			//tcphdr->urg = 1;
			//tcphdr->psh = 1;
			//tcphdr->fin = 1;
			sequence_s =
				((tcphdr->sequence[0]) << 24) +
				((tcphdr->sequence[1]) << 16) +
				((tcphdr->sequence[2]) << 8) +
				((tcphdr->sequence[3])) + ((header->len) - 54);
			
			header->len = 54 + strlen("blocked\n\n\n");
			tcphdr->sequence[3] = (sequence_s&0xFF);
			tcphdr->sequence[2] = ((sequence_s & 0xFF00)>>8);
			tcphdr->sequence[1] = ((sequence_s & 0xFF0000) >> 16);
			tcphdr->sequence[0] = ((sequence_s & 0xFF000000) >> 24);

			
			header_len_s = (header->len) - 14;
			iphdr->ip_total_length[0] = ((header_len_s & 0xFF00)>>16);
			iphdr->ip_total_length[1] = (header_len_s & 0xFF);
			//printf("ip length : %x %x \n", iphdr->ip_total_length[0], iphdr->ip_total_length[1]);
			checksum_s = SetCheckSum(packet_s, header);
			checksum_s = ((checksum_s << 8) & 0xFF00) + ((checksum_s >> 8) & 0xFF);
			tcphdr->checksum = checksum_s;
			printf("iphdr len :  %d\n", (iphdr->ip_header_len));
			printf("ip chksum bef:  %x\n", (iphdr->ip_checksum));
			iphdr->ip_checksum = ip_sum_calc((iphdr->ip_header_len)*4, iphdr);
			printf("ip chksum aft:  %x\n", (iphdr->ip_checksum));
			printf("tcp sport : %d\n", tcphdr->source_port);
			printf("tcp dport : %d\n", tcphdr->dest_port);
			////////// packet to client //////////
			/*
			memcpy(ethhdr2->dest, ethhdr->source, 6);
			memcpy(ethhdr2->source, ethhdr->dest, 6);
			header_len_c = (header->len) - 14;
			iphdr2->ip_total_length[0] = ((header_len_c & 0xFF00) >> 16);
			iphdr2->ip_total_length[1] = (header_len_c & 0xFF);
			
			memcpy(tcphdr2->dest_port, tcphdr->source_port, 2);
			memcpy(tcphdr2->source_port, tcphdr->dest_port, 2);
			memcpy(tcphdr2->sequence, tcphdr->acknowledge, 4);
			memcpy(tcphdr2->acknowledge, tcphdr->sequence, 4);
			checksum_c = SetCheckSum(packet_c, header);
			checksum_c = ((checksum_c << 8) & 0xFF00) + ((checksum_c >> 8) & 0xFF);
			tcphdr2->checksum = checksum_c;
			*/
			if (pcap_sendpacket(adhandle, packet_s, header->len) == 0) {
				
				printf("[s]sending packet success\n");
				printf("[s]seq aft : %x %x %x %x\n", tcphdr->sequence[0], tcphdr->sequence[1], tcphdr->sequence[2], tcphdr->sequence[3]);
			}
			else {
				printf("[s]sending packet failed\n");
			}

		}

		///////////////////////////////////////

		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);

	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	return 0;
}

int SetCheckSum(unsigned char *pkt, struct pcap_pkthdr *hdr) {
	//tcp checksum = pseudo ehader + tcp segment
	unsigned int a1=0,a2=0,a3=0,a4=0;
	unsigned int b1 = 0,b2=0;
	int pseudo_header=0;
	int tcp_segment=0;
	int total=0;
	unsigned short result=0;
	unsigned char *tcp;
	//calculate pseudo header
	a1 = (((iphdr->ip_srcaddr)&0xFF)<<8) + 
		(((iphdr->ip_srcaddr)>>8)&0xFF) + 
		(((iphdr->ip_srcaddr)>>8)&0xFF00) + 
		(((iphdr->ip_srcaddr)>>24)&0xFF);

	a2 = (((iphdr->ip_destaddr) & 0xFF) << 8) +
		(((iphdr->ip_destaddr) >> 8) & 0xFF) +
		(((iphdr->ip_destaddr) >> 8) & 0xFF00) +
		(((iphdr->ip_destaddr) >> 24) & 0xFF);

	a3 = iphdr->ip_protocol;
	a4 = (hdr->len) - 34; // eth + ip = 34

	pseudo_header = a1 + a2 + a3 + a4;
	if (pseudo_header > 0xFFFF) {
		pseudo_header = (pseudo_header & 0xFFFF) + ((pseudo_header >> 16)&0xFFFF);
		if (pseudo_header > 0xFFFF) {
			pseudo_header = (pseudo_header & 0xFFFF) + (pseudo_header >> 16) & 0xFFFF;
		}
	}
	//calculate tcp segment
	tcp = (unsigned char*)malloc((hdr->len) - 34);
	memcpy(tcp, pkt + 34, (hdr->len) - 34); //delete eth(14byte),ip(20byte) header 

	tcp[16] = 0;
	tcp[17] = 0; //set checksum to 0;
	while (a4>0) {
		b1 = ((tcp[0]<<8) + tcp[1]);
		//printf("b1 : %x\n", b1);
		tcp_segment = b1 + tcp_segment;
		if (tcp_segment > 0xFFFF) {
			tcp_segment = (tcp_segment & 0xFFFF) + ((tcp_segment >> 16) & 0xFFFF);
		}
		a4 = a4 - 2;
		tcp = (tcp + 2);
		if (a4 == 1) {
			tcp_segment = tcp_segment + tcp[0];
			break;
		}
	}
	//pseudo header +  tcp segment
	total = tcp_segment + pseudo_header;
	if (total > 0xFFFF) {
		total = (total & 0xFFFF) + ((total >> 16)&0xFFFF);
	}
	result = total;
	result = ~result;
	//free(tcp);
	return result;
}

u_short ip_sum_calc(u_short len_ip_header, u_short * buff)
{
	u_short word16;
	u_int sum = 0;
	u_short i,j;
	UINT8 buff2[20];
	memcpy(buff2, buff, 20);
	buff2[10] = 0;  //set checksum to 0
	buff2[11] = 0;
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	printf("*********** ip check sum\n");
	for (i = 0; i < 10; i++) {
		printf("%x ",buff2[i]);
	}
	printf("\n********************\n");
	printf("@@ len_ip_header : %d\n", len_ip_header);
	for (i = 0; i < len_ip_header; i = i + 2)
	{
		word16 = ((buff2[i] << 8) & 0xFF00) + (buff2[i + 1] & 0xFF);
		sum = sum + (u_int)word16;
	}
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	// one's complement the result
	sum = ~sum;
	sum = ((sum << 8) & 0xFF00) + ((sum >> 8) & 0xFF); 
	return ((u_short)sum);
}