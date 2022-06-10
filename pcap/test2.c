#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <string.h>

//for mariadb insert function
#include <mariadb/mysql.h>

int gbl_cnt = 0;
//int insert_cnt = 1;

MYSQL mysql;
MYSQL* mysqlPtr = NULL;
MYSQL_RES* Result = NULL;
MYSQL_ROW Row;
int stat;

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
		print_hex_ascii_line(ch, len, offset);
		return;
	}
	
	// data spans multiple lines
	// begin for loop1
	for ( ;; ) {
		// compute current line length
		line_len = line_width % len_rem;
		//print line
		print_hex_ascii_line(ch, line_len, offset);
		// compute total remaining
		len_rem = len_rem - line_len;
		// shift pointer to remaining bytes to print
		ch = ch + line_len;
		// add offset
		offset = offset + line_width;
		//check if we have line width chars or less
		if ( len_rem <= line_width ) {
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
	
	//print offset
	printf("%05d   ", offset);
	
	ch = payload;
	
	// print hex ascii
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	 	if ( i == 7 ) {
	 		printf(" ");
	 	}
	 }
	 
	 // print space to handle line less than 8 bytes
	 if ( len < 8 )
	 	printf(" ");
	 
	 //fill hex gap with spaces if not full line
	 if ( len < 16 ) {
	 	gap = 16 - len ;
	 	for ( i = 0; i < gap; i++) {
	 		printf("   ");
	 	}
	 }
	 printf("   ");
	 
	 // print raw char
	 ch = payload;
	 for ( i = 0; i < len; i++ ) {
	 	if ( isprint(*ch) )
	 		printf("%c", *ch);
	 	else
	 		printf(".");
	 	ch++;
	 }
	 
	 printf("\n");
	
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;

	printf("got packet - %d\n", gbl_cnt++);
	printf("packet-length = %d\n", header->len);
	printf("packet-data = \n");
	
	print_payload(packet, header->len);	
	
	ip = (struct sniff_ip*) (packet + sizeof(struct sniff_ethernet));
	
	tcp = (struct sniff_tcp*) (packet + sizeof(struct sniff_ethernet)
					+ sizeof(struct sniff_ip) );
	
	unsigned char ip_src_array[4] = "\x00\x00\x00\x00";
	unsigned char ip_dst_array[4] = "\x00\x00\x00\x00";
	char ip_src_str[16] = { " "};
	char ip_dst_str[16] = { " "};
	
	unsigned short int  tcp_sport =0;
	unsigned short int  tcp_dport =0;
	
	memcpy ( ip_src_array, &(ip->ip_src), 4 );
	memcpy ( ip_dst_array, &(ip->ip_dst), 4 );
	
	//printf("IP SRC : %02x %02x %02x %02x\n",
	printf("IP SRC : %u.%u.%u.%u .\n",
			(unsigned char) ip_src_array[0],
			(unsigned char) ip_src_array[1], 
			(unsigned char) ip_src_array[2],
			(unsigned char) ip_src_array[3]
		);
		
	//printf("IP DST : %02x %02x %02x %02x\n",
	printf("IP DST : %u.%u.%u.%u .\n",
			(unsigned char) ip_dst_array[0],
			(unsigned char) ip_dst_array[1], 
			(unsigned char) ip_dst_array[2],
			(unsigned char) ip_dst_array[3]
		);
		
	
	sprintf(ip_src_str , "%u.%u.%u.%u",
			(unsigned char) ip_src_array[0],
			(unsigned char) ip_src_array[1], 
			(unsigned char) ip_src_array[2],
			(unsigned char) ip_src_array[3]
		);
		
	sprintf(ip_dst_str , "%u.%u.%u.%u",
			(unsigned char) ip_dst_array[0],
			(unsigned char) ip_dst_array[1], 
			(unsigned char) ip_dst_array[2],
			(unsigned char) ip_dst_array[3]
		);
	printf("INFO: ip_src_str = %s\n" , ip_src_str);
	printf("INFO: ip_dst_str = %s\n" , ip_dst_str);
	
	// print tcp port data
	printf("Src Port = %d\n", ntohs(tcp->th_sport));
	printf("Dst Port = %d\n", ntohs(tcp->th_dport));
	
	tcp_sport = ntohs(tcp->th_sport);
	tcp_dport = ntohs(tcp->th_dport);
	
	char* Query = NULL;
	
	Query = (char*)malloc(1048576);
	memset(Query, 0x00, 1048576);
	
	// date time string array . ex) "2022-03-02 10:11:12.123456"
	char current_time [32];
	
	/*
	time_t mytime = time(NULL);

	char * time_str = ctime(&mytime);
	strftime(current_time, 31, "%Y-%m-%d %H:%M:%S", mytime);
	//time_str[strlen(time_str)-1] = '\0';
	//printf("Current Time : %s\n", time_str);
	
	//strcpy(current_time, time_str);
	*/
	
	time_t now;
	now = time(NULL);
	struct tm *mytime = localtime(&now);
	strftime(current_time, 31, "%Y-%m-%d %H:%M:%S", mytime);
	
	printf("DEBUG: current time : %s, \n", current_time);
	
	/*
	sprintf(Query, "INSERT INTO tb_packet_data  ( \
			 src_ip, dst_ip, src_port, dst_port, create_at ) VALUES ( \
				'%s', \
				'%s', \
				%u, \
				%u, \
				'%s' \
				)",
			ip_src_str,	// src_ip
			ip_dst_str,	// dst_ip
			tcp_sport,	// src_port
			tcp_dport,	// dst_port 
			current_time	// create_at
	);
	*/
	
	sprintf(Query, "select * from blocklist");
	
	
		
	stat = mysql_query(mysqlPtr, Query);
	if (stat != 0) {
		printf("ERROR: mariadb query error: %s\n", mysql_error(&mysql));
	}
	
	Result = mysql_store_result(mysqlPtr);
	
	
	unsigned int j = 0;
		 
	    while((Row = mysql_fetch_row(Result)) != NULL)
	    {
	    	for (unsigned int i = 0; i < Result->field_count; i++)
	    		printf("%s ", Row[i]);
	    		
	   	printf("\n");
	    	
	 //   	block_list[j].id = j;
	//    	strcpy(block_list[j].host, Row[0]);
	//    	strcpy(block_list[j].ip_str, Row[2]);
	//    	j++;
	    }
	    
	    //free(Query);
	    
	  
	    //mysql_close(mysqlPtr);
    
  
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	if(Result == NULL) {
		printf("DEBUG: no result data .\n");
		return 0;
	}
	
	if(Query != NULL) {
		free(Query);
		Query = NULL;
	}
	
	if(Result != NULL) {
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
	if (mysqlPtr == NULL) {
		printf("Mariadb connect error(%s/%d) : %s\n", __FUNCTION__, __LINE__,mysql_error(&mysql) );
		 
		return 1;
	}
	else {
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
	ret = pcap_loop(handle, 0, got_packet, NULL);
	
	
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	
	if (mysqlPtr != NULL) {
		mysql_close(mysqlPtr);
		mysqlPtr = NULL;
	}
	
	return(0);
}
