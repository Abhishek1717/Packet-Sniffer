# Packet-Sniffer

This project was done to understand how raw socket interface and packet header parsing works.
A raw socket allows an application to directly access lower-layer protocols, which means a raw socket receives un-extracted packets. 
There is no need to provide the port and IP address to a raw socket, unlike in the case of the stream and the datagram sockets.
In this project, i  got the experience of: 1) working with protocol headers at datalink, network, and transport layer, 2) designing data structures for the header of each protocol, and 3) mapping the header fields from the buffer in which packet has been received on to the data structure.
