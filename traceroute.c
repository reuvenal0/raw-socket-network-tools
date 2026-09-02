#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> 
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// Matala requirements
#define MAX_HOPS 30
#define PROBES_PER_HOP 3
#define TIMEOUT_MS 1000

#define ICMP_PAYLOAD_SIZE 56 // Standart ICMP msg size
// Size calculation for buffers:
#define IP_HEADER_SIZE (sizeof(struct iphdr)) 
#define ICMP_PACKET_SIZE (sizeof(struct icmphdr) + ICMP_PAYLOAD_SIZE)
#define FULL_PACKET_SIZE (IP_HEADER_SIZE + ICMP_PACKET_SIZE)
// Receive buffer (Large enough to hold a full IP packet + ICMP)
#define RECV_BUF_SIZE 2048

// checksum fun from tirgul 5-8 :)
// checksum - standard 1s complement checksum
// Calculate checksum for ICMP packet (header and data)
unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

/* Helper: convert (end-start) to milliseconds */
static double diff_ms(const struct timespec *start, const struct timespec *end) {
    long sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    return (double)sec * 1000.0 + (double)nsec / 1e6;
}

int main(int argc, char **argv) {
    // destention IP str:
    const char *dest_ip_str = NULL;

    // Get the parameters via the OPT functions:
    int opt;
    while ((opt = getopt(argc, argv, "a:")) != -1) {
        switch (opt) {
            case 'a':
                dest_ip_str = optarg;
                break;
            default:
                // we need 'a', else is not good:
                fprintf(stderr, "no 'a' parameter\n");
                return 1;
        }
    }

    if (!dest_ip_str) {
        // we need 'a'...
        fprintf(stderr, "no 'a' parameter\n");
        return 1;
    }

    // Build destination address (standart IPV4)
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;

    if (inet_pton(AF_INET, dest_ip_str, &dest.sin_addr) != 1) {
        // convert IP to str failed so IP not valid
        fprintf(stderr, "Invalid IPv4 address: %s\n", dest_ip_str);
        return 1;
    }

    // Create raw socket for sending custom IP packets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        // Socket failed 
        perror("socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
        return 1;
    }

    // Tell kernel that we include the IP header ourselves
    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sock);
        return 1;
    }

    // id helps to tie a response to our request (using the "PID with AND 0xFFFF" for ICMP in 16-bit)
    unsigned short my_id = (unsigned short)(getpid() & 0xFFFF);
    // seq is raised on each probe, to identify each attempt
    unsigned short seq = 1;

    // Print log to user:
    printf("traceroute to %s, %d hops max, %d probes per hop\n",
           dest_ip_str, MAX_HOPS, PROBES_PER_HOP);

    // Main loop over TTL/hops:
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        // for each hop print the ***
        printf("%2d  ", ttl);
        fflush(stdout); // flush to refresh the screem each hop

        char hop_ip_first[INET_ADDRSTRLEN] = {0}; // Save the first IP returned with the same TTL, to print it once
        int reached_destination = 0; // Stop flag if we reached the destination

        // Each probe is an independent sending of an ICMP Echo Request packet with the same TTL, Sending three probes improves reliability and allows for packet loss detection.
        for (int probe = 0; probe < PROBES_PER_HOP; probe++) {
            // Set a buffer for the packet we send 
            unsigned char packet[FULL_PACKET_SIZE];
            memset(packet, 0, sizeof(packet)); // set all the val in the array to 0

            // Build IP header
            struct iphdr *ip = (struct iphdr *)packet;
            ip->version = 4; // IPv4...
            ip->ihl = (unsigned char)(IP_HEADER_SIZE / 4); // number of 32-bit words
            ip->tos = 0;
            ip->tot_len = htons((unsigned short)FULL_PACKET_SIZE);
            ip->id = htons((unsigned short)(my_id + ttl)); // any changing ID is fine
            ip->frag_off = htons(0);
            ip->ttl = (unsigned char)ttl; /// the TTL we send...
            ip->protocol = IPPROTO_ICMP;
            ip->saddr = 0;
            ip->daddr = dest.sin_addr.s_addr;

            ip->check = 0;
            ip->check = checksum(ip, IP_HEADER_SIZE);

            // Build ICMP Echo Request
            struct icmphdr *icmp = (struct icmphdr *)(packet + IP_HEADER_SIZE);
            icmp->type = ICMP_ECHO; // 8
            icmp->code = 0;
            icmp->un.echo.id = htons(my_id);
            icmp->un.echo.sequence = htons(seq++);

            // Payload: can be anything; we fill with a pattern...
            unsigned char *payload = (unsigned char *)(packet + IP_HEADER_SIZE + sizeof(struct icmphdr));
            for (int i = 0; i < ICMP_PAYLOAD_SIZE; i++) {
                payload[i] = (unsigned char)('A' + (i % 26));
            }

            icmp->checksum = 0;
            icmp->checksum = checksum(icmp, ICMP_PACKET_SIZE);

            // Send probe and measure time
            struct timespec t_start, t_end;
            clock_gettime(CLOCK_MONOTONIC, &t_start);

            ssize_t sent = sendto(sock, packet, FULL_PACKET_SIZE, 0,
                                  (struct sockaddr *)&dest, sizeof(dest));
            if (sent < 0) {
                // if the send failed we print '*' and try again
                perror("sendto");
                printf("* ");
                continue;
            }

            // Wait for a reply using poll() with a timeout (non-blocking wait)
            struct pollfd pfd;
            pfd.fd = sock; // The raw ICMP socket we are listening on
            pfd.events = POLLIN; // We are interested only in incoming data

            int pr = poll(&pfd, 1, TIMEOUT_MS);
            if (pr <= 0) {
                // timeout or error: print '*' and try again
                printf("* ");
                fflush(stdout);
                continue;
            }

            // Receive packet
            // Buffer to store the received packet
            unsigned char recvbuf[RECV_BUF_SIZE];

            // Structure to store sender (router / destination) address
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);


            // Receive the packet from the socket
            ssize_t n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                                 (struct sockaddr *)&from, &fromlen);
            if (n < 0) {
                // error: print '*' and try again
                printf("* ");
                fflush(stdout);
                continue;
            }

            // stop the timer and calculator the RTT:
            clock_gettime(CLOCK_MONOTONIC, &t_end);
            double rtt = diff_ms(&t_start, &t_end);

            // Parse outer IP header from received packet:
            // Make sure we received at least a full IP header
            if (n < (ssize_t)sizeof(struct iphdr)) {
                // not valid IP header so let's try again
                printf("* ");
                fflush(stdout);
                continue;
            }

            // Parse the outer IP header from the received packet
            struct iphdr *rip = (struct iphdr *)recvbuf;
            // IP header length is stored in 32-bit words, so multiply by 4
            int rip_hlen = rip->ihl * 4;

            // Verify that the packet also contains a full ICMP header
            if (n < rip_hlen + (ssize_t)sizeof(struct icmphdr)) {
                // to short ICMP header 
                printf("* ");
                fflush(stdout);
                continue;
            }

            // pointer to the ICMP header (right after the IP header)
            struct icmphdr *ricmp = (struct icmphdr *)(recvbuf + rip_hlen);

            // Convert source IP to string
            char hop_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, hop_ip, sizeof(hop_ip));

            // Determine if this ICMP message corresponds to our probe.
            int is_ours = 0;

            // Check the ICMP message type we received
            if (ricmp->type == ICMP_ECHOREPLY) {
                // Verify that this reply matches our process ID
                if (ntohs(ricmp->un.echo.id) == my_id) {
                    is_ours = 1; // This reply belongs to our probe
                    reached_destination = 1; // We reached the final destination
                }
            } else if (ricmp->type == ICMP_TIME_EXCEEDED || ricmp->type == ICMP_DEST_UNREACH) {
                // Make sure we have embedded original IP header:
                // Routers send TIME_EXCEEDED (TTL expired) or DEST_UNREACH
                // These ICMP messages contain the *original packet* inside them

                // Point to the embedded (inner) IP header inside the ICMP payload
                unsigned char *inner = (unsigned char *)(recvbuf + rip_hlen + sizeof(struct icmphdr));
                
                // Length of the embedded data
                ssize_t inner_len = n - (rip_hlen + (ssize_t)sizeof(struct icmphdr));

                // Make sure we have at least an IP header inside
                if (inner_len >= (ssize_t)sizeof(struct iphdr)) {
                    // Parse the outer IP header from the received packet
                    struct iphdr *inner_ip = (struct iphdr *)inner;
                    // IP header length is stored in 32-bit words, so multiply by 4
                    int inner_hlen = inner_ip->ihl * 4;

                    // Make sure the embedded packet also contains an ICMP header
                    if (inner_len >= inner_hlen + (ssize_t)sizeof(struct icmphdr)) {
                        // pointer to the ICMP header (right after the IP header)
                        struct icmphdr *inner_icmp = (struct icmphdr *)(inner + inner_hlen);

                        // Verify that the embedded packet is our ICMP Echo Request
                        if (inner_ip->protocol == IPPROTO_ICMP &&
                            ntohs(inner_icmp->un.echo.id) == my_id) {
                                // This ICMP error refers to our probe
                                is_ours = 1;
                        }
                    }
                }
            }

            if (!is_ours) {
                // If the ICMP message is not related to our probe, treat as timeout for this probe.
                printf("* ");
                fflush(stdout);
                continue;
            }

            // Print hop IP once (typical traceroute style), unless it changes
            if (hop_ip_first[0] == '\0') {
                // First response for this hop
                strncpy(hop_ip_first, hop_ip, sizeof(hop_ip_first) - 1);
                hop_ip_first[sizeof(hop_ip_first) - 1] = '\0';
                printf("%s  ", hop_ip_first);
            } else if (strcmp(hop_ip_first, hop_ip) != 0) {
                // Rare, but possible: different routers responding for different probes
                printf("%s  ", hop_ip);
            }

            // Print the round-trip time for this probe
            printf("%.2f ms ", rtt);
            fflush(stdout);
        }


        // End of probes for this TTL
        printf("\n");

        // Stop traceroute once the destination replied
        if (reached_destination) {
            break;
        }
    }

    
    // Close the raw socket before exiting
    close(sock);
    return 0;
}