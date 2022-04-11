# STEFAN MAGIRESCU - 325CC

*I implemented everything except for the bonus task*

Once the packet is received, I check its type, in order to treat it as supposed to.

- An ARP message can be either a request made by somebody who needs to find out my MAC, or a reply to my request.
In case of a request, I need to reply my MAC address. Therefore, I update the ARP header with the proper information
and send it back to its source. In case of a reply, I first check to see if I still have the message (which presumably
I saved for later because I had the IP address of the destination, but not the MAC address of the next hop, so I had
to ask for it myself with an ARP request). If no message is found, I drop the packet, or else I update the headers of 
the message with the right MAC address and send it on its way, but not before adding the IP-MAC entry to my ARP table in
case I further need it later.

- An ICMP message checks for proper connectivity. In case I receive an ECHO, I will reply to it to let the source know
I'm alive and well. After I check for the TTL and checksum, I must send an ICMP error message if TTL is out of date and therefore, I drop the packet. If not, I proceed to calculate the best route to get to the destination. Again, if not found, I send an ICMP error message.

- Now I update the TTL and checksum to let the next host know the packet has been processed by myself.

- If I have the best route MAC in my ARP table, I send the packet and it all ends here, however chances are this won't be the case and I will have to request the MAC address associated to the desired destination IP address, which I do by sending an ARP request and saving the message for later, when/if I receive an ARP reply.

- I chose to traverse the routing table using binary sort, after having sorted the table primarily by prefix and then
by mask.