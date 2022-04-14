#include "skel.h"
#include "queue.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	uint8_t thisMACAddress[6];
	uint32_t thisIPAddress;

	// INITIALIZE QUEUE
	queue myQueue = queue_create();

	// READ ROUTING TABLE
	struct route_table_entry *rtable = (struct route_table_entry *)malloc(65000 * sizeof(struct route_table_entry));
	int rtable_size = read_rtable(argv[1], rtable);

	// SORT ROUTING TABLE
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp);

	// INITIALIZE ARP TABLE
	struct arp_entry *arp_table = (struct arp_entry *)malloc(65000 * sizeof(struct arp_entry));
	int arp_size = 0;

	while (1)
	{
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// parse ethernet and ip headers
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		// save the values of the router's addresses into vars
		get_interface_mac(m.interface, thisMACAddress);
		thisIPAddress = inet_addr(get_interface_ip(m.interface));

		// check if the message is of type ARP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{
			// parse ARP header
			struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			// check if the message is of type ARP request
			if (htons(arp_hdr->op) == ARPOP_REQUEST)
			{
				// send an ARP reply
				ARPRply(arp_hdr, eth_hdr, thisMACAddress, m.interface);
			}

			// check if the message is of type ARP reply
			if (htons(arp_hdr->op) == ARPOP_REPLY && !queue_empty(myQueue))
			{
				// send the latest queued packet to the newly found destination
				ARPRplyRec(myQueue, arp_table, arp_hdr, arp_size);
			}
			continue;
		}

		// check if the message is of type IP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			// check if message is of type ICMP
			if (ip_hdr->protocol == 1)
			{
				// parse icmp header
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

				// if message was meant for me, send a reply
				if (icmp_hdr->type == ICMP_ECHO && ip_hdr->daddr == thisIPAddress)
				{
					ICMP(ip_hdr->saddr, thisIPAddress, eth_hdr, m.interface, ICMP_ECHOREPLY);
					continue;
				}
			}

			// if ttl is invalid, send a notice back to its source and drop the packet
			if (ip_hdr->ttl <= 1)
			{
				printf("ttl mic\n");
				ICMP(ip_hdr->saddr, thisIPAddress, eth_hdr, m.interface, ICMP_TIME_EXCEEDED);
				continue;
			}

			// if checksum is invalid, drop the packet
			if (ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr)) != 0)
			{
				continue;
			}

			// find the best route for the packet to get to the destination
			struct route_table_entry *route = get_best_route(rtable, ntohl(ip_hdr->daddr), rtable_size);

			// if the destination is unreachable, send a notice to the sender and drop the packet
			if (route == NULL)
			{
				ICMP(ip_hdr->saddr, thisIPAddress, eth_hdr, m.interface, ICMP_DEST_UNREACH);
				continue;
			}

			// if everything is fine, update ttl and checksum
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));

			// check if next dest's ip is tied to its mac address in the arp table
			struct arp_entry *nextDest = arpRouteFinder(arp_table, route->next_hop, arp_size);

			// if destination's mac is known, update the ethernet header and send the packet
			if (nextDest)
			{
				ETHMaker(eth_hdr, nextDest->mac, NULL, eth_hdr->ether_type, route->interface);
				m.interface = route->interface;
				send_packet(&m);
			}
			else
			{
				// else, send ARP request
				// prepare ETH Header
				uint8_t brdcastAddress[] = {255, 255, 255, 255, 255, 255};
				ETHMaker(eth_hdr, brdcastAddress, NULL, htons(ETHERTYPE_ARP), route->interface);

				// enqueue packet
				packet queuePkt;
				queuePkt.interface = route->interface;
				queuePkt.len = m.len;
				memcpy(queuePkt.payload, m.payload, m.len);
				queue_enq(myQueue, &queuePkt);

				// send ARP request
				ARPReq(eth_hdr, route->next_hop, inet_addr(get_interface_ip(route->interface)), route->interface);
			}
		}
	}
}