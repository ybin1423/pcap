#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
// for mariadb insert function .
#include <mariadb/mysql.h>

int gbl_cnt = 0;


//global variables ...
char if_bind_global[]="enp0s3";
//char if_bind_global[]="lo";
int if_bind_global_len=6;
//int if_bind_global_len=2;

int sendraw_mode=1;

//struct trust_host_ip_list *trust_list=NULL;
struct block_host_ip_list *gbl_block_list=NULL;
int gbl_block_list_length=0;

#define SUPPORT_OUTPUT

MYSQL mysql;
MYSQL* mysqlPtr = NULL;
MYSQL_RES* Result = NULL;
MYSQL_ROW Row;
int stat;	//check query result

u_char* pre_packet;


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct pseudohdr  {
    u_int32_t saddr;      // 발신자의 IP.
    u_int32_t daddr;      // 수신자의 IP.
    u_int8_t useless;    // 아직 사용되지 않음.
    u_int8_t protocol;   // 프로토콜.
    u_int16_t tcplength;  // TCP 헤더의 길이.
};

void print_chars(char * ch ,int num)
{
	return;
}

unsigned short in_cksum(u_short *addr, int len)

{

    int         sum=0;        // 총 합계.
    int         nleft=len;    // 인자로 받은 len.
    u_short     *w=addr;      // 인자로 받은 addr의 주소를 저장.
    u_short     answer=0;     // 최종적으로 리턴되는 값.
    // nleft만큼 sum에 *w의 값을 더함. 

    while (nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
  
    // nleft가 홀수라서 값이 남을 경우 추가로 더해줌.
    if (nleft == 1){
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);  // 상위 16비트와 하위 16비트를 더함.
    sum += (sum >> 16);                  // carry bit 값을 더함.
    answer = ~sum;                       // 값을 반전 시킴.
    return(answer);                      // 리턴.
}

void print_payload_right(const u_char* packet, int size)
{
	return;
}


int sendraw( u_char* pre_packet, int mode)
{
      const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

      u_char packet[1600];
        int raw_socket;
        int on=1;        
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;    
        int port; 
        int pre_payload_size = 0 ;
      u_char *payload = NULL ;
      int size_vlan = 0 ;
      int size_vlan_apply = 0 ;
      int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
 
      int setsockopt_result = 0 ;
      int prt_sendto_payload = 0 ;
      char* ipaddr_str_ptr ;

      int warning_page;
      int vlan_tag_disabled = 0 ;

      int ret = 0 ;

      #ifdef SUPPORT_OUTPUT
      print_chars('\t',6);
      printf( "\n[raw socket sendto]\t[start]\n\n" );

      if (size_payload > 0 || 1) {
         print_chars('\t',6);
         printf("   pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);         
         print_payload_right(pre_packet, 100);
      }
      //m-debug
      printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
      #endif

        for( port=80; port<81; port++ ) {
         #ifdef SUPPORT_OUTPUT
         print_chars('\t',6);
         printf("onetime\n");
         #endif
         // raw socket 생성
         raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
         if ( raw_socket < 0 ) {
            print_chars('\t',6);
            fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
            fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
            return -2;
         }
	 printf("DEBUG socket function return = %d \n", raw_socket);
         int tmp = setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));
	 
	 printf("DEBUG setsockopt return = %d\n", tmp);
	 
         if ( if_bind_global != NULL ) {
            setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len );

            if( setsockopt_result == -1 ) {
               print_chars('\t',6);
               fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
               return -2;
            }
            #ifdef SUPPORT_OUTPUT
            else {
               print_chars('\t',6);
               fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", if_bind_global, setsockopt_result, strerror(errno));
            }
            #endif

         }

         ethernet = (struct sniff_ethernet*)(pre_packet);
         
         printf("DEBUG ethernet type = %x\n", ethernet->ether_type );
         
         if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) {
            #ifdef SUPPORT_OUTPUT
            printf("vlan packet\n");
            #endif
            size_vlan = 4;
            memcpy(packet, pre_packet, size_vlan);
         } else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
            #ifdef SUPPORT_OUTPUT
            printf("normal packet\n");
            #endif
            size_vlan = 0;
         } else {
            fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
         }

         vlan_tag_disabled = 1 ;
         if ( vlan_tag_disabled == 1 ) {
            size_vlan_apply = 0 ;
            memset (packet, 0x00, 4) ;
         } else {
            size_vlan_apply = size_vlan ;
         }
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)(packet + size_vlan_apply) ;
                memset( iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + size_vlan_apply + 20);
                memset( tcphdr, 0, 20 );

            #ifdef SUPPORT_OUTPUT
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
            #endif

            source_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;   // twist s and d address
            dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;      // for return response
            iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;
            int pre_tcp_header_size = 0;
            char pre_tcp_header_size_char = 0x0;
            pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
            pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

            tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;      // twist s and d port
            tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;      // for return response
            tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
            tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
            tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;

                tcphdr->doff = 5;

                tcphdr->ack = 1;
                tcphdr->psh = 1;

                tcphdr->fin = 1;
                

             
                
                // 가상 헤더 생성.
                pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->useless = (u_int8_t) 0;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

            #ifdef SUPPORT_OUTPUT
            // m-debug
            printf("DEBUG: &packet == \t\t %p \n" , &packet);
            printf("DEBUG: pseudo_header == \t %p \n" , pseudo_header);
            printf("DEBUG: iphdr == \t\t\t %p \n" , iphdr);
            printf("DEBUG: tcphdr == \t\t\t %p \n" , tcphdr);
            printf("sizeof(struct pseudohdr) = %d\n", sizeof(struct pseudohdr));
   
            #endif


            // choose output content
            warning_page = 5;
            if ( warning_page == 5 ){
               // write post_payload ( redirecting data 2 )
               //post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
               post_payload_size = 226 + 82  ;   // Content-Length: header is changed so post_payload_size is increased.
                    //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
               memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
                                    "Content-Length: 226\x0d\x0a"
                                    "Content-Type: text/html"
                                    "\x0d\x0a\x0d\x0a"
                                    "<html>\r\n"
                                    "<head>\r\n"
                                    "<meta charset=\"UTF-8\">\r\n"
                                    "<title>\r\n"
                                    "CroCheck - WARNING - PAGE\r\n"
                                                "SITE BLOCKED - WARNING - \r\n"
                                    "</title>\r\n"
                                    "</head>\r\n"
                                    "<body>\r\n"
                                    "<center>\r\n"
                                    "<img src=\"http://192.168.111.100:80/warning.png\">\r\n"
                                                "<h1> SITE BLOCKED </h1>\r\n"
                                    "</center>\r\n"
                                    "</body>\r\n"
                                    "</html>", post_payload_size ) ;
                }
            pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);
             	 

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                //iphdr->tot_len = 40;
                iphdr->tot_len = htons(40 + post_payload_size);
		
		
            #ifdef SUPPORT_OUTPUT
            //m-debug
            printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
            #endif

            iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);

            memset( (char*)iphdr + 6 , 0x40 , 1 );

                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));
          	 
                address.sin_family = AF_INET;

            address.sin_port = tcphdr->dest ;
            address.sin_addr.s_addr = dest_address.s_addr;

            prt_sendto_payload = 0;
            #ifdef SUPPORT_OUTPUT
            prt_sendto_payload = 1 ;
            #endif

            if( prt_sendto_payload == 1 ) {

            print_chars('\t',6);
            printf("sendto Packet data :\n");

            print_chars('\t',6);
            printf("       From: %s(%hhu.%hhu.%hhu.%hhu)\n",
                        inet_ntoa( source_address ),
                        ((char*)&source_address.s_addr)[0],
                        ((char*)&source_address.s_addr)[1],
                        ((char*)&source_address.s_addr)[2],
                        ((char*)&source_address.s_addr)[3]
                  );
            print_chars('\t',6);
            printf("         To: %s(%hhu.%hhu.%hhu.%hhu)\n",
                        inet_ntoa( dest_address ),
                        ((char*)&dest_address.s_addr)[0],
                        ((char*)&dest_address.s_addr)[1],
                        ((char*)&dest_address.s_addr)[2],
                        ((char*)&dest_address.s_addr)[3]
                  );

            switch(iphdr->protocol) {
               case IPPROTO_TCP:
                  print_chars('\t',6);
                  printf("   Protocol: TCP\n");
                  break;
               case IPPROTO_UDP:
                  print_chars('\t',6);
                  printf("   Protocol: UDP\n");
                  return -1;
               case IPPROTO_ICMP:
                  print_chars('\t',6);
                  printf("   Protocol: ICMP\n");
                  return -1;
               case IPPROTO_IP:
                  print_chars('\t',6);
                  printf("   Protocol: IP\n");
                  return -1;
               case IPPROTO_IGMP:
                  print_chars('\t',6);
                  printf("   Protocol: IGMP\n");
                  return -1;
               default:
                  print_chars('\t',6);
                  printf("   Protocol: unknown\n");
                  //free(packet_dmp);
                  return -2;
            }

            print_chars('\t',6);
            printf("   Src port: %d\n", ntohs(tcphdr->source));
            print_chars('\t',6);
            printf("   Dst port: %d\n", ntohs(tcphdr->dest));

            payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

            size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

            printf("DEBUG: sizeof(struct iphdr) == %lu \t , \t tcphdr->doff * 4 == %hu \n",
                        sizeof(struct iphdr) , tcphdr->doff * 4);
                        
                        
                      
            

            if (size_payload > 0 || 1) {
               print_chars('\t',6);
               printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
               
               //print_payload(payload, size_payload);
               
               print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
            }

            if (size_payload > 0 || 1) {
               print_chars('\t',6);
               printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
               
    //           print_payload(payload, size_payload);
               
               print_payload_right((const u_char*)&packet, 40);
            }

            if (size_payload > 0) {
               print_chars('\t',6);
               printf("   Payload (%d bytes):\n", size_payload);
               
     //          print_payload(payload, size_payload);
               
               print_payload_right(payload, size_payload);
            }
         } // end -- if -- prt_sendto_payload = 1 ;
            if ( mode == 1 ) {
                    sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;
               if ( sendto_result != ntohs(iphdr->tot_len) ) {
                  fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
                  ret = -10 ;
               } else {
                  ret = 1 ;
               }
              } // end if(mode)
                //} // end for loop

            
                close( raw_socket );
                
        } // end for loop
      #ifdef SUPPORT_OUTPUT
        printf( "\n[sendraw] end .. \n\n" );
      #endif
      //return 0;
      return ret ;
}







void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset = 0;
	const u_char *ch = payload;
	
	if ( len <= 0 )
		return;
	
	// data fits on one line
	if ( len <= line_width ) {
		print_hex_ascii_line(ch , len , offset);
		return;
	}
	
	// data spans multiple lines 
	// begin for loop1
	for ( ;; ) {
		// compute current line length 
		line_len = line_width % len_rem;
		// print line
		print_hex_ascii_line(ch, line_len, offset);
		// compute total remaining
		len_rem = len_rem - line_len;
		// shift pointer to remaining bytes to print
		ch = ch + line_len;
		// add offset 
		offset = offset + line_width;
		// check if we have line width chars or less 
		if (len_rem <= line_width ) {
			// print last line ad get out
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	// end for loop 1
	
	return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;
    
    
    // print offset 
    printf("%05d   ", offset);
    
    ch = payload;
    
    // print hex ascii
    for ( i = 0 ; i < len ; i++ ) {
    	printf("%02x ", *ch);
    	ch++;
    	if ( i == 7 ) {
    		printf(" ");
    	}
    }
    
    // print space to handle line less than 8 bytes 
    if ( len < 8 )
    	printf(" ");
    	
    // fill hex gap with spaces if not full line 
    if ( len < 16 ) {
    	gap = 16 - len ;
    	for ( i = 0 ; i < gap ; i++) {
    		printf("   ");
    	}
    }
    
    printf("   ");
    
    // print raw char
    ch = payload;
    for ( i = 0 ; i < len ; i++ ) {
    	if ( isprint(*ch) )
    		printf("%c", *ch);
    	else
    		printf(".");
    	ch++;
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {
    
    struct block_host_ip_list *block_list = NULL;
    int block_list_length;
    
    struct sniff_ethernet *ethernet;    
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;
    int ret;
    
    block_list = gbl_block_list;
    block_list_length = gbl_block_list_length;
    
    ret = sendraw(packet, sendraw_mode);
    
    printf("DEBUG ret = %d\n", ret);
    
    printf("got_packet - %d\n", gbl_cnt++);
    printf("packet-length = %d\n", header->len);
    printf("packet-data = \n");
   
    print_payload(packet, header->len);
    

    
    ethernet = (struct sniff_ethernet*) (packet);
    
    ip = (struct sniff_ip*) ( packet + sizeof(struct sniff_ethernet));
    
    tcp = (struct sniff_tcp*) ( packet + sizeof(struct sniff_ethernet) 
    					+ sizeof(struct sniff_ip) );

    //printf("DEBUG ethernet type = %x\n", ethernet->ether_type );
    
    printf("MAC src : %02x-%02x-%02x-%02x-%02x-%02x\n",
    		ethernet->ether_shost[0],
    		ethernet->ether_shost[1],
    		ethernet->ether_shost[2],
    		ethernet->ether_shost[3],
    		ethernet->ether_shost[4],
    		ethernet->ether_shost[5]
    	);
    printf("MAC dst : %02x-%02x-%02x-%02x-%02x-%02x\n",
    		ethernet->ether_dhost[0],
    		ethernet->ether_dhost[1],
    		ethernet->ether_dhost[2],
    		ethernet->ether_dhost[3],
    		ethernet->ether_dhost[4],
    		ethernet->ether_dhost[5]
    	);	
	
	

    unsigned char ip_src_array[4] = "\x00\x00\x00\x00";
    unsigned char ip_dst_array[4] = "\x00\x00\x00\x00";
    char ip_src_str[16] = { " " };
    char ip_dst_str[16] = { " " };
    
    unsigned short int tcp_sport = 0;
    unsigned short int tcp_dport = 0;
    
    memcpy ( ip_src_array , &(ip->ip_src) , 4 );
    memcpy ( ip_dst_array , &(ip->ip_dst) , 4 );
    
    
    sprintf(ip_src_str , "%u.%u.%u.%u" 
    		, (unsigned char) ip_src_array[0]
    		, (unsigned char) ip_src_array[1]
    		, (unsigned char) ip_src_array[2]
    		, (unsigned char) ip_src_array[3]
    );
    sprintf(ip_dst_str , "%u.%u.%u.%u" 
    		, (unsigned char) ip_dst_array[0]
    		, (unsigned char) ip_dst_array[1]
    		, (unsigned char) ip_dst_array[2]
    		, (unsigned char) ip_dst_array[3]
    );
    
    
    //printf("IP src : %u.%u.%u.%u .\n"
    printf("IP src : %02x %02x %02x %02x .\n"    
    		, (unsigned char) ip_src_array[0]
    		, (unsigned char) ip_src_array[1]
    		, (unsigned char) ip_src_array[2]
    		, (unsigned char) ip_src_array[3]    		    		
    );

 
    printf("IP src = %s\n" , ip_src_str ) ;
    
    //printf("IP dst : %u.%u.%u.%u .\n"
    printf("IP dst : %02x %02x %02x %02x .\n"   
    		, (unsigned char) ip_dst_array[0]
    		, (unsigned char) ip_dst_array[1]
    		, (unsigned char) ip_dst_array[2]
    		, (unsigned char) ip_dst_array[3]    		    		
    );
    
    
    printf("IP dst = %s\n" , ip_dst_str ) ;     


    
    // print tcp port data 
    printf("Src Port = %d\n" , ntohs(tcp->th_sport) );

    printf("Dst Port = %d\n" , ntohs(tcp->th_dport) );

    tcp_sport = ntohs(tcp->th_sport);
    tcp_dport = ntohs(tcp->th_dport);
    
    
    char* Query = NULL;
    Query = (char*)malloc(1048576);
    memset(Query, 0x00, 1024*1024);
    
    // date time string array . ex ) "2022-03-02 10:11:12.123456"
    char current_time[32] ;
    
    /*
    time_t mytime = time(NULL);
    char * time_str = ctime(&mytime);
    strftime(current_time, 31 , "%Y-%m-%d %H:%M:%S", mytime);
    //time_str[strlen(time_str)-1] = '\0';
    //printf("Current Time : %s\n", time_str);
    //strcpy(current_time, time_str);
    */
    
    time_t now;
    now = time(NULL);
    struct tm *mytime = localtime(&now);
    strftime(current_time, 31 , "%Y-%m-%d %H:%M:%S", mytime);
    
    printf("DEBUG: current_time : %s .\n" , current_time );
    
  //  printf("DEBUG : IP LENGTH = %d\n",  IP_HL(ip) * 4);
  //  printf("DEBUG : TCP LENGTH = %x\n", (tcp->th_offx2)>>4);
    
    
    char *result = NULL;
    char *result2 = NULL;
    int host_name_len = 0;
    int payload_len;
    u_char *packet_payload;
    
    packet_payload = ( packet + sizeof(struct sniff_ethernet) 
    					+ sizeof(struct sniff_ip)
    					+ sizeof(struct sniff_tcp)  );
    
    payload_len = ntohs(ip->ip_len) - (IP_HL(ip) * 4) - (((tcp->th_offx2)>>4) * 4);
    
    
    printf("DEBUG : PAYLOAD LENGTH = %d\n", payload_len);
    
    
    char *host_name = NULL;
    host_name = (char*)malloc(256);
    memset(host_name, 0x00, 256);
    
    if ( payload_len != 0 ) {
    
    	result = strstr (packet_payload, "GET / HTTP/" );	
    	if ( (u_char*) result == (u_char*)packet_payload ) {
    		result = strstr ( packet_payload, "Host: " );
    		if ( result != NULL ) {
    			result2 = strstr ( result, "\r" );
    		}
    	}
    	host_name_len = result2 - result;
    }
    
    printf("DEBUG: host_name_len = %d\n", host_name_len);
    
    if ( host_name_len > 6 ) {
    	strncpy ( host_name, result + 6, host_name_len - 6);
    	 
    }
    if ( host_name_len > 0 ) {
    	printf("http host header is %s.\n", host_name ); 
    }
    
    
        
    sprintf(
    	Query, "INSERT INTO tb_packet_data ( \
    			domain, src_ip , dst_ip , src_port , dst_port , create_at ) VALUES ( \
    			 '%s', \    			
    			 '%s', \
    			 '%s', \
    			 %u , \
    			 %u ,\
    			 '%s' \
    			 )",
    		host_name,	//domain
    		ip_src_str, // src_ip
    		ip_dst_str, // dst_ip
    		tcp_sport , // src_port
    		tcp_dport ,  // dst_port
    		current_time // create_at
    );
   
    stat = mysql_query(mysqlPtr,Query);
     
    if( stat != 0 ) {
	    printf("ERROR: mariadb query error: %s\n", mysql_error(&mysql));
    }
    
    Result = mysql_store_result(mysqlPtr);
    			
    if ( Result == NULL ) {
    	printf("DEBUG: no result data .\n");
    	return 0;
    }			
    
    if ( Query != NULL ) {
    	free(Query);
    	Query = NULL;
    }
    if ( Result != NULL ){
    	mysql_free_result(Result);
    	Result = NULL;
    }
    
    printf("\n");
    
  
    
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	
	printf("pcap started...\n");

	mysql_init(&mysql);
	
	mysqlPtr = mysql_real_connect(&mysql, "127.0.0.1", "testuser", "testuserpass", "testdb100", 3306, (char*) NULL, 0);
	if ( mysqlPtr == NULL ) {
		printf( "Mariadb connect error(%s/%d): %s\n", __FUNCTION__, __LINE__, mysql_error(&mysql) );
		
		return 1;
	} else {
		printf( "INFO: DB connect success .\n");
	}
	

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	//int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
	int ret = 0;
	//ret = pcap_loop(handle, 10, got_packet, NULL);
	
	
	
	
	pcap_loop(handle, 0, got_packet, NULL);
	
	
	
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	
	if ( mysqlPtr != NULL ) {
		mysql_close(mysqlPtr);
		mysqlPtr = NULL;
	}
	
	return(0);
}
