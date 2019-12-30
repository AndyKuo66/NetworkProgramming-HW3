#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
int countip = 0;

//ethernet header
typedef struct eth_hdr { 
	u_char dst_mac[6]; 
	u_char src_mac[6]; 
	u_short eth_type; 
}eth_hdr; 
eth_hdr *ethernet;

//IPV4 header 
typedef struct ip4_hdr { 
	int version:4; 
	int header_len:4; 
	u_char tos:8; 
	int total_len:16; 
	int ident:16; 
	int flags:16; 
	u_char ttl:8; 
	u_char protocol:8; 
	int checksum:16; 
	u_char sourceIP[4]; 
	u_char destIP[4]; 
}ip4_hdr; 
ip4_hdr *ip4;

//IPV6 header
typedef struct ip6_hdr{
	u_int version:4;
	u_int traffic_class:8;
	u_int flow_label:20;
	uint16_t payload_len;
	u_char protocol:8; 
	uint8_t hop_limit;
	uint16_t sourceIP[8];
	uint16_t destIP[8];
}ip6_hdr;
ip6_hdr *ip6;

//TCP header
typedef struct tcp_hdr { 
	u_short sport; 
	u_short dport; 
	u_int seq; 
	u_int ack; 
	u_char head_len; 
	u_char flags; 
	u_short wind_size; 
	u_short check_sum; 
	u_short urg_ptr; 
}tcp_hdr; 
tcp_hdr *tcp;

//UDP header 
typedef struct udp_hdr { 
	u_short sport; 
	u_short dport; 
	u_short tot_len; 
	u_short check_sum; 
}udp_hdr; 
udp_hdr *udp;

int main(int argc,char *argv[]){
	countip = 0;//count how many ip
    	pcap_t *handle;                  
    	char errbuf[PCAP_ERRBUF_SIZE]; 
    	bpf_u_int32 mask;              
    	bpf_u_int32 net;              
    	struct bpf_program filter;      
	printf("Open : %s\n",argv[2]);
	handle=pcap_open_offline(argv[2],errbuf);
    	pcap_loop(handle,-1,packet_handler,NULL);
    	pcap_close(handle);
	printf("-----------------finish------------------\n"); 
	printf("Total : %d\n",countip);

    	return 0;
}




void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data){
	static int count=0;
	count++;
	printf("-----------------------------------------\n"); 
	printf("packet #%d\n",count);		//packet number
	printf("capture time: %s",ctime((const time_t*)&pkt_header->ts.tv_sec));//get packet time

	
	//length of header
	u_int eth_len=sizeof(struct eth_hdr); 
	u_int ip4_len=sizeof(struct ip4_hdr);
	u_int ip6_len=sizeof(struct ip6_hdr); 
	u_int tcp_len=sizeof(struct tcp_hdr); 
	u_int udp_len=sizeof(struct udp_hdr); 
	printf("ethernet information:\n"); 
	ethernet=(eth_hdr *)pkt_data; 
	printf("Src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , ethernet->src_mac[0], ethernet->src_mac[1], ethernet->src_mac[2], ethernet->src_mac[3], ethernet->src_mac[4], ethernet->src_mac[5]);
	printf("Dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , ethernet->dst_mac[0], ethernet->dst_mac[1], ethernet->dst_mac[2], ethernet->dst_mac[3], ethernet->dst_mac[4], ethernet->dst_mac[5]);
 

	//IPV4
	if(ntohs(ethernet->eth_type)==0x0800){ 
		countip++;
		printf("IPV4 is used\n"); 
		printf("IPV4 header information:\n"); 
		ip4=(ip4_hdr*)(pkt_data+eth_len); 
		printf("Src IP : %d.%d.%d.%d\n",ip4->sourceIP[0],ip4->sourceIP[1],ip4->sourceIP[2],ip4->sourceIP[3]); 
		printf("Dst IP : %d.%d.%d.%d\n",ip4->destIP[0],ip4->destIP[1],ip4->destIP[2],ip4->destIP[3]); 
		if(ip4->protocol==6){ 	//TCP Protocl
			printf("TCP is used\n"); 
			tcp=(tcp_hdr*)(pkt_data+eth_len+ip4_len); 
			printf("TCP src port : %u\n",htons(tcp->sport)); 
			printf("TCP dst port : %u\n",htons(tcp->dport)); 
		}
		else if(ip4->protocol==17){ //UDP Protocl
			printf("UDP is used\n"); 
			udp=(udp_hdr*)(pkt_data+eth_len+ip4_len); 
			printf("UDP src port : %u\n",htons(udp->sport)); 
			printf("UDP dst port : %u\n",htons(udp->dport));
		 } 
		else if(ip4->protocol==1){ //TCMP Protocl
			printf("TCMP is used\n"); 
		}
		else { 
			printf("other transport protocol is used\n"); 
		} 
	} 
	//IPV6
	else if(ntohs(ethernet->eth_type)==0x086dd) { 
		countip++;
		printf("IPV6 is used\n"); 
		ip6=(ip6_hdr*)(pkt_data+eth_len);
		char str[INET6_ADDRSTRLEN];
		printf("Src ip6 :%s\n",inet_ntop(AF_INET6,ip6->sourceIP,str,sizeof(str)));
		printf("Dst ip6 :%s\n",inet_ntop(AF_INET6,ip6->destIP,str,sizeof(str)));
                if(ip6->protocol==6){	//TCP Protocl
                        printf("TCP is used\n");
                        tcp=(tcp_hdr*)(pkt_data+eth_len+ip6_len);
                        printf("TCP src port : %u\n",htons(tcp->sport));
                        printf("TCP dst port : %u\n",htons(tcp->dport));
                }
                else if(ip6->protocol==17){	//UDP Protocl
                        printf("UDP is used\n");
                        udp=(udp_hdr*)(pkt_data+eth_len+ip6_len);
                        printf("UDP src port : %u\n",htons(udp->sport));
                        printf("UDP dst port : %u\n",htons(udp->dport));
                 }
		else if(ip6->protocol==1){ //TCMP Protocl
			printf("TCMP is used\n"); 
		}
                else {
                        printf("other transport protocol is used\n");
                }
	} 
	else{
		printf("other ethernet_type\n");
	}

}


