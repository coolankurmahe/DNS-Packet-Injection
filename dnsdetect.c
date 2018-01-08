#include <stdio.h>
#include <pcap.h>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include <netdb.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net/if.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>


#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>



#include <resolv.h>
#include <sys/ioctl.h>


#include <unistd.h>
#include <net/ethernet.h>



#define IPSIZE 16



#define PACSIZE 8192


/* Reference: http://www.ccs.neu.edu/home/*/


struct ethernetheader {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};


struct dns_header {
	char id[2];
	char flags[2];
	char ancount[2];
	char nscount[2];
	char arcount[2];
	char qdcount[2];
};


// DNS ques
struct dns_ques {
	char *qname;
	char qtype[2];
	char qclass[2];
};


/* used for easy addition */
static int array_size = 0;

/* Node representing data in the database */
struct node {
	u_short id;	// Keeping as u_short as easy to store, compare and handle DB
	int listsize;
	char ip[20][32];
	struct node *next;
};


/* The callback function for pcap_loop */
void detectDNSPoisioning(struct node *database, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethernetheader *ether;


	struct iphdr *ip;
	struct udphdr *udp;


	struct dns_ques question;
	struct dns_header *dnshdr;


	u_short id;
	char *answerstart;

	u_int ipheadersize;
	char request[150], *domainname;
	
	int possible_attack;

	int idfound;
	char *hex_id;
	int indInDB;
	


	u_int ip_index;
	u_short type;
	u_short class;
	u_short resp_size;


	int epochtime;		/* for calculating time for packet */
	time_t epochtimeastime;

	char new_ip_list[20][32];
	char ipfrompacket[32];


	struct tm * timeinfo;

	int size;
	int i = 1;
	int j = 0; 
	int k;
	/* define ethernet header */
	ether = (struct ethernetheader*)(packet);
	ip = (struct iphdr*)(((char*)packet) + 14);

	/* udp header */
	ipheadersize = ip->ihl * 4;
	udp = (struct udphdr*)(((char*) ip) + ipheadersize);

	/* dns header */
	dnshdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));

	/* start of question */
	question.qname = ((char *)dnshdr + 12);

	/*
	 * parse domain name
	 * [3]www[7]example[3]com -> www.example.com
	 */
	domainname = question.qname;
	size = domainname[0];



	while (size > 0) 
	{
		for (k = 0; k < size; k++) 
		{
			request[j++] = domainname[i + k];
		}
		request[j++] = '.';
		i += size;
		size = domainname[i++];
	}
	request[--j] = '\0';

	/* start of answer */
	answerstart = (char *)question.qname + j + 6;

	/* Saving current ID of DNS */
	id = *((u_short *)dnshdr->id);
	hex_id = dnshdr->id;

	possible_attack = 0;
	k = 0;	// This value of k is used as a reference in other places. Shouldn't be touched.
	for (i = 0; i < htons(*((u_short *)(dnshdr->ancount))); i++) 
	{
		type = ((u_short *)(answerstart + 2))[0];
		class = ((u_short *)(answerstart + 4))[0];
		resp_size = ((u_short *)(answerstart + 10))[0];

		idfound = 0;
		if (htons(type) == 1) 
		{	
			//  Type A dns are evaluated
			ip_index = ((u_int *)(answerstart + 12))[0]; 
			sprintf(ipfrompacket, "%u.%u.%u.%u", ((u_char *)(&ip_index))[0],
			        ((u_char *)(&ip_index))[1],
			        ((u_char *)(&ip_index))[2],
			        ((u_char *)(&ip_index))[3]);

			/* check if ID already present in database, and hence an attack */
			for (j = 0; j < array_size; j++) 
			{
				if (id == database[j].id) 
				{
					indInDB = j;
					possible_attack = 1;
					idfound = 1;
				}
			}

			// create a list of all the IPs in this answer
			strcpy(new_ip_list[k++], ipfrompacket);

			
			answerstart = answerstart + 16;
		} 
		else 
		{	
			answerstart = answerstart + 12 + htons(resp_size);
		}


	}

	// If the item  not present  in DB, insert new one
	if (idfound == 0) 
	{
		for (i = 0; i < k; i++) 
		{
			database[array_size].id = id;
			strcpy(database[array_size].ip[i], new_ip_list[i]);
		}
		database[array_size].listsize = k;
		array_size += 1;
	}

	/* warn user if possible attack */
	if (possible_attack == 1) 
	{
		/* get time from packet header */
		epochtime = header->ts.tv_sec;
		epochtimeastime = epochtime;
		timeinfo = localtime(&epochtimeastime);

		printf("\nDNS poisoning attempt detected!!!\n");
		printf("Timestamp: %s", asctime(timeinfo));
		printf("TXID: 0x");
		printf("%x", (int)(*(u_char *)(hex_id)));
		printf("%x\t", (int)(*(u_char *)(hex_id + 1)));
		printf("Request: %s\n", request);
		printf("Answer1 [");
		for (i = 0; i < database[indInDB].listsize; i++) 
		{
			if (i + 1 == database[indInDB].listsize) 
			{
				printf("%s", database[indInDB].ip[i]);
			} 
			else 
			{
				printf("%s, ", database[indInDB].ip[i]);
			}
		}
		printf("]\n");
		printf("Answer2 [");
		for (i = 0; i < k; i++) 
		{
			if (i + 1 == k) 
			{
				printf("%s", new_ip_list[i]);
			} 
			else 
			{
				printf("%s, ", new_ip_list[i]);
			}
		}
		printf("]\n");
	}
}

void isDetector()
{
	int i,j,k,m;

	i = 2;
	j = 8;

	k = i+ j;
	//To detect the false positives , we need to detect whther the I.P is the real I.P
	return;

}


void applyFilter()
{
	//The application if filter will be done in this function;

	int isfilter = 0;

	if(isfilter == 1)
	{

	}
	return;
}
int main(int argc, char *argv[])
{
	char *dev = NULL;
	
	char *bpffilterexp;			
				
		
	char errbuffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;


	int interface_provided = 0;
	int read_file = 0;
	char *dnsfilter = "udp and src port domain";	
	int bpffilter = 0;
	int option = 0;

	bpf_u_int32 net;
	bpf_u_int32 mask;
	pcap_t *handle;	


	char *filename;
	struct node database[1000];

	/* Complete filter expression */
	char *filterexprs;	

	memset(errbuffer, 0, PCAP_ERRBUF_SIZE);

	
	/* Parse the command line arguments */
	while ((option = getopt(argc, argv, "i:r:t")) != -1) {
		switch (option) {
		case 'i':
			if (interface_provided) {
				printf("More than one device  not supported  \n");
				exit(EXIT_FAILURE);
			}
			dev = optarg;
			interface_provided = 1;
			break;
		case 'r':
			if (read_file) {
				printf("More than one file  not supported \n");
				exit(EXIT_FAILURE);
			}
			filename = optarg;
			read_file = 1;
			break;
		case 't':
			printf("help\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			printf("Exiting .missing argument or unknown option..\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		bpffilterexp = argv[optind];
		bpffilter = 1;
	}

	/* if interface not provided by user, set through pcap library */
	if (interface_provided != 1) {
		dev = pcap_lookupdev(errbuffer);
		if (dev == NULL) {
			fprintf(stderr, "default device not found: %s\n", errbuffer);
			exit(EXIT_FAILURE);
		}
	}

	isDetector();

	/*
	 * get IPv4 network numbers and corresponding network mask
	 * (the network number is the IPv4 address ANDed with the network mask
	 * so it contains only the network part of the address).
	 * This was essential because we needed to know the network mask
	 * in order to apply the filter
	 */
	if (pcap_lookupnet(dev, &net, &mask, errbuffer) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}


	/*
	 * create handle for the file provided by user,
	 * or open device to read.
	 */
	if (read_file == 1) {
		handle = pcap_open_offline(filename, errbuffer);   //call pcap library function
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open pcap file %s: %s\n", filename, errbuffer);
			exit(EXIT_FAILURE);
		} else {
			printf("Opened file %s\n\n", filename);
		}
	} else {
		handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuffer);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuffer);
			exit(EXIT_FAILURE);
		} else {
			printf("Listening on device: %s\n\n", dev);
		}
	}

	applyFilter();
	//  BPF filter 
	if (bpffilter == 1) {
		filterexprs = malloc(strlen(dnsfilter) + strlen(bpffilterexp) + 6);
		strcpy(filterexprs, dnsfilter);
		strcat(filterexprs, " and ");
		strcat(filterexprs, bpffilterexp);
	} else {
		filterexprs = malloc(strlen(dnsfilter) + 1);
		strcpy(filterexprs, dnsfilter);
	}

	
	if (pcap_compile(handle, &fp, filterexprs, 0, 0) == -1) {
		fprintf(stderr, " filter not parsed %s: %s\n", filterexprs,
		        pcap_geterr(handle));
		goto free_filter;
	}

	/* application of  the filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, " filter not instaled  %s: %s\n", filterexprs,
		        pcap_geterr(handle));
		goto free_filter;
	}

	
	pcap_loop(handle, -1, (pcap_handler)detectDNSPoisioning, (u_char *)database);

	
	pcap_freecode(&fp);
	pcap_close(handle);

free_filter:
	free(filterexprs);
	return 0;
}
