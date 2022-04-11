#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s, (struct sockaddr *)&addr, sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet *socket_receive_message(int sockfd, packet *m)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(packet *m)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	int ret;
	ret = write(interfaces[m->interface], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m)
{
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1)
	{
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
		{
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set,
					 NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
		{
			if (FD_ISSET(interfaces[i], &set))
			{
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else
	{
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else
	{
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++)
	{
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

void init(int argc, char *argv[])
{
	for (int i = 0; i < argc; ++i)
	{
		printf("Setting up interface: %s\n", argv[i]);
		interfaces[i] = get_sock(argv[i]);
	}
}

uint16_t icmp_checksum(uint16_t *data, size_t size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *data++;
		size -= sizeof(unsigned short);
	}
	if (size)
		cksum += *(unsigned short *)data;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (uint16_t)(~cksum);
}

uint16_t ip_checksum(uint8_t *data, size_t size)
{
	// Initialise the accumulator.
	uint64_t acc = 0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset = ((uintptr_t)data) & 3;
	if (offset)
	{
		size_t count = 4 - offset;
		if (count > size)
			count = size;
		uint32_t word = 0;
		memcpy(offset + (char *)&word, data, count);
		acc += ntohl(word);
		data += count;
		size -= count;
	}

	// Handle any complete 32-bit blocks.
	char *data_end = (char *)data + (size & ~3);
	while ((char *)data != data_end)
	{
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}

	size &= 3;

	// Handle any partial block at the end of the data.
	if (size)
	{
		uint32_t word = 0;
		memcpy(&word, data, size);
		acc += ntohl(word);
	}

	// Handle deferred carries.
	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16)
	{
		acc = (acc & 0xffff) + (acc >> 16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset & 1)
	{
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

int read_rtable(const char *path, struct route_table_entry *rtable)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		p = strtok(line, " .");
		i = 0;
		while (p != NULL)
		{
			if (i < 4)
				*(((unsigned char *)&rtable[j].prefix) + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&rtable[j].next_hop) + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&rtable[j].mask) + i % 4) = atoi(p);

			if (i == 12)
				rtable[j].interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		j++;
	}
	return j;
}

int cmp(const void *a, const void *b)
{
	struct route_table_entry *x = (struct route_table_entry *)a;
	struct route_table_entry *y = (struct route_table_entry *)b;

	return (x->prefix != y->prefix) ? (x->prefix - y->prefix) : (x->mask - y->mask);
}

int parse_arp_table(char *path, struct arp_entry *arp_table)
{
	FILE *f;
	fprintf(stderr, "Parsing ARP table\n");
	f = fopen(path, "r");
	DIE(f == NULL, "Failed to open arp_table.txt");
	char line[100];
	int i = 0;
	for (i = 0; fgets(line, sizeof(line), f); i++)
	{
		char ip_str[50], mac_str[50];
		sscanf(line, "%s %s", ip_str, mac_str);
		fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
		arp_table[i].ip = inet_addr(ip_str);
		int rc = hwaddr_aton(mac_str, arp_table[i].mac);
		DIE(rc < 0, "invalid MAC");
	}
	fclose(f);
	fprintf(stderr, "Done parsing ARP table.\n");
	return i;
}

// update ETH header with the given info
void ETHMaker(struct ether_header *eth_hdr, uint8_t *dest, uint8_t *src, uint16_t type, int interface)
{
	memcpy(eth_hdr->ether_dhost, dest, 6);
	eth_hdr->ether_type = type;
	if (interface != -1)
	{
		get_interface_mac(interface, eth_hdr->ether_shost);
	}
	else
	{
		memcpy(eth_hdr->ether_shost, src, 6);
	}
}

// update ARP header with the given info
void ARPMaker(struct arp_header *arp_hdr, uint8_t *destHardware, uint8_t *srcHardware,
			  uint32_t destIP, uint32_t srcIP, uint16_t op)
{
	arp_hdr->htype = htons(ARPHRD_ETHER);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->op = op;
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	memcpy(arp_hdr->sha, srcHardware, 6);
	memcpy(arp_hdr->tha, destHardware, 6);
	arp_hdr->spa = srcIP;
	arp_hdr->tpa = destIP;
}

// look through the ARP table and try to find the MAC associated with the IP
struct arp_entry *arpRouteFinder(struct arp_entry *table, uint32_t ip, int size)
{
	for (int i = 0; i < size; i++)
	{
		if (table[i].ip == ip)
			return &table[i];
	}
	return NULL;
}

void ARPRply(struct arp_header *arp_hdr,
			 struct ether_header *eth_hdr, uint8_t *thisMACAddress, int interface)
{
	// update the ethernet header with the right src, dest and type
	ETHMaker(eth_hdr, arp_hdr->sha, thisMACAddress, htons(ETHERTYPE_ARP), -1);

	// update the ethernet header with the right src, dest and type
	ARPMaker(arp_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost, arp_hdr->spa, inet_addr(get_interface_ip(interface)), htons(ARPOP_REPLY));

	// make a new packet with the above data and send it
	send_packet(pktMaker(eth_hdr, NULL, NULL, arp_hdr, interface));
}

void ARPRplyRec(queue q, struct arp_entry *arp_table, struct arp_header *arp_hdr, int arpSize)
{
	// update the arp table with the replied mac address
	arp_table[arpSize].ip = arp_hdr->spa;
	memcpy(arp_table[arpSize++].mac, arp_hdr->sha, 6);

	// get the first packet from the queue
	packet *deQueuedPkt = (packet *)queue_deq(q);

	// parse ethernet header
	struct ether_header *eth_hdr_reply = (struct ether_header *)deQueuedPkt->payload;

	// update the ethernet header with the right info
	uint8_t mac[6];
	get_interface_mac(deQueuedPkt->interface, mac);
	ETHMaker(eth_hdr_reply, arp_hdr->sha, mac, htons(ETHERTYPE_IP), -1);

	send_packet(deQueuedPkt);
}

void ARPReq(uint32_t destIP, uint32_t srcIP, struct ether_header *eth_hdr,
			int interface)
{
	// update ARP header with the right info and send it
	struct arp_header *arp_hdr = (struct arp_header *)malloc(sizeof(struct arp_header));
	ARPMaker(arp_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost, destIP, srcIP, htons(ARPOP_REQUEST));
	send_packet(pktMaker(eth_hdr, NULL, NULL, arp_hdr, interface));
}

void ICMP(uint32_t destIP, uint32_t srcIP, struct ether_header *ethHead,
		  int interface, uint8_t type)
{

	struct ether_header *eth_hdr = (struct ether_header *)malloc(sizeof(struct ether_header));
	struct iphdr *ip_hdr = (struct iphdr *)malloc(sizeof(struct iphdr));
	struct icmphdr *icmp_hdr = (struct icmphdr *)malloc(sizeof(struct icmphdr));

	// set ETH Header
	ETHMaker(eth_hdr, eth_hdr->ether_shost, NULL, htons(ETHERTYPE_IP), interface);

	// set IP Header
	ip_hdr->version = 4;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = htons(getpid() & 0xFFFF);
	ip_hdr->daddr = destIP;
	ip_hdr->saddr = srcIP;
	ip_hdr->frag_off = 0;
	ip_hdr->tos = 0;
	ip_hdr->ihl = 5;
	ip_hdr->ttl = 100;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum((uint8_t *)&ip_hdr, sizeof(struct iphdr));

	// set ICMP Header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	// prepare packet and send it
	send_packet(pktMaker(eth_hdr, ip_hdr, icmp_hdr, NULL, interface));
}

packet *pktMaker(struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, struct arp_header *arp_hdr, int interface)
{
	packet *pkt = (packet *)malloc(sizeof(packet));

	// attach ethernet header and update packet's interface
	pkt->interface = interface;
	memcpy(pkt->payload, eth_hdr, sizeof(struct ether_header));

	// attach ip and icmp headers to the packet
	if (icmp_hdr != NULL)
	{
		memcpy(pkt->payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
		memcpy(pkt->payload + sizeof(struct ether_header) + sizeof(struct iphdr),
			   icmp_hdr, sizeof(struct icmphdr));
		pkt->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	}
	// attach arp header to the packet
	if (arp_hdr != NULL)
	{
		memcpy(pkt->payload + sizeof(struct ethhdr), arp_hdr, sizeof(struct arp_header));
		pkt->len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	}

	return pkt;
}

struct route_table_entry *get_best_route(struct route_table_entry *rtable, uint32_t dest_ip, int rtable_size)
{
	// int ans = binSearch(0, rtable_size, dest_ip, rtable);

	// return ans == -1 ? NULL : &rtable[ans];

	int idx = -1;
	for (int i = 0; i < rtable_size; i++)
	{
		if ((dest_ip & ntohl(rtable[i].mask)) == ntohl(rtable[i].prefix))
		{
			if (idx == -1 || ntohl(rtable[idx].mask) < ntohl(rtable[i].mask))
				idx = i;
		}
	}

	if (idx == -1)
		return NULL;

	return &rtable[idx];
}

int binSearch(int l, int r, uint16_t ip, struct route_table_entry *rtable)
{
	if (l > r)
		return -1;

	int mid = l + (r - l) / 2;
	int prefix = ntohl(rtable[mid].mask) & ip;

	// if (prefix == ntohl(rtable[mid].prefix))
	// {
	// 	if (ntohl(rtable[mid].mask) == ip)
	// 	{
	// 		return mid;
	// 	}
	// 	if (ntohl(rtable[mid].mask) > ip)
	// 	{
	// 		return binSearch(l, mid - 1, ip, rtable);
	// 	}

	// 	return binSearch(mid + 1, r, ip, rtable);
	// }
	if (prefix == ntohl(rtable[mid].prefix))
	{
		while (prefix == ntohl(rtable[mid].prefix))
		{
			mid++;
		}
		return mid;
	}

	if (ntohl(rtable[mid].prefix) > prefix)
	{
		return binSearch(l, mid - 1, ip, rtable);
	}
	return binSearch(mid + 1, r, ip, rtable);
}