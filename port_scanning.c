#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PORT_MIN 1
#define PORT_MAX 65535
#define TCP_TIMEOUT_MS 120

// TCP Pseudo header for checksum calculation
struct pseudo_tcp {
    uint32_t saddr, daddr;  // Source and destination IP addresses
    uint8_t zero, proto;    // Zero padding and protocol number
    uint16_t tcp_len;       // TCP segment length
};

// Standard checksum function (from tirgul)
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    
    // Sum all 16-bit words
    for (; len > 1; len -= 2) sum += *buf++;
    
    // Handle trailing byte if length is odd
    if (len == 1) sum += *(unsigned char *)buf;
    
    // Fold 32-bit sum into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    // Return one's complement
    return (unsigned short)~sum;
}

// Resolve hostname or IP string to IPv4 address
int resolve_ipv4(const char *host, struct in_addr *out) {
    // Try to parse as direct IP address first
    if (inet_pton(AF_INET, host, out) == 1) {
        // We got a valid IP already, no DNS lookup is required
        return 0;
    }
    
    // Otherwise, perform DNS resolution
    struct addrinfo hints = {.ai_family = AF_INET}, *res = NULL; // Restricts results to IPv4
    
    // Perform DNS resolution for the given hostname
    if (getaddrinfo(host, NULL, &hints, &res) || !res) {
        // DNS resolution failed
        return -1;
    }
    
    // Extract the IPv4 address from the result
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    
    // Free memory allocated by getaddrinfo
    freeaddrinfo(res);

    return 0; // Success - we now have a valid IP
}

// Determines the local IPv4 address that would be used to send packets to a given destination
// Uses the "idle UDP socket trick" - no actual packets are sent
int get_local_ip(struct in_addr dst, struct in_addr *src) {
    // Create an IPv4 UDP socket (no packets are actually sent)
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    // Prepare destination address (IPv4, port 53 DNS as a dummy port)
    struct sockaddr_in d = {
        .sin_family = AF_INET,
        .sin_addr   = dst,
        .sin_port   = htons(53)  // DNS port (arbitrary choice)
    };

    // "Connect" the UDP socket to force route selection
    // This doesn't send any data, just sets up routing
    if (connect(s, (struct sockaddr *)&d, sizeof(d)) < 0) {
        close(s);
        return -1;
    }

    // Length parameter required by getsockname
    socklen_t len = sizeof(d);

    // Query the socket for its locally assigned address
    if (getsockname(s, (struct sockaddr *)&d, &len) < 0) {
        close(s);
        return -1;
    }

    // Extract the local IPv4 address
    *src = d.sin_addr;

    // Close the socket
    close(s);

    return 0; // Success
}

// Compute IP header checksum (only header, no payload)
uint16_t ip_checksum(struct iphdr *ip) {
    // Clear the checksum field before calculation 
    ip->check = 0;
    
    // Compute checksum over the IPv4 header (ihl is in 32-bit words)
    return checksum(ip, ip->ihl * 4);
}

// Compute TCP checksum using pseudo header
uint16_t tcp_checksum(const struct iphdr *ip,
                      const struct tcphdr *tcp,
                      size_t len) {

    // Build the TCP pseudo-header required for checksum calculation
    struct pseudo_tcp ph = {
        ip->saddr,       // Source IPv4 address
        ip->daddr,       // Destination IPv4 address
        0,               // Reserved field (must be zero)
        IPPROTO_TCP,     // Protocol identifier for TCP
        htons(len)       // TCP segment length (header + payload)
    };

    // Temporary buffer for pseudo-header + TCP segment
    unsigned char buf[sizeof(ph) + sizeof(struct tcphdr)];

    // Copy pseudo-header into the buffer
    memcpy(buf, &ph, sizeof(ph));

    // Copy TCP header and payload after the pseudo-header
    memcpy(buf + sizeof(ph), tcp, len);

    // Compute and return the checksum over the combined buffer
    return checksum(buf, sizeof(ph) + len);
}

/**
 * Sends a minimal IPv4/TCP RST packet (optionally with ACK) to the destination.
 * Assignment requirement: send RST either way (open or closed port)
 *
 * @param sock    A raw socket (SOCK_RAW) used to send the packet
 * @param src     Source IPv4 address to place in the IP header
 * @param dst     Destination IPv4 address to place in the IP header
 * @param sp      Source TCP port
 * @param dp      Destination TCP port
 * @param seq     TCP sequence number to use in the RST segment
 * @param ack     TCP acknowledgment number to use if do_ack != 0
 * @param do_ack  If non-zero, set the TCP ACK flag and include ack number
 */
void send_rst(int sock, struct in_addr src, struct in_addr dst, 
              uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack, int do_ack)
{
    // Allocate a zero-initialized packet buffer: IPv4 header + TCP header (no payload)
    unsigned char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
    
    // Pointer to the IP header at the start of the buffer
    struct iphdr *ip = (struct iphdr *)pkt;
    
    // Point to the TCP header right after the IP header
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    
    // Build IP header
    ip->ihl = 5;                        // Header length (5 * 4 = 20 bytes)
    ip->version = 4;                    // IPv4
    ip->ttl = 64;                       // Time to live
    ip->protocol = IPPROTO_TCP;         // TCP protocol
    ip->tot_len = htons(sizeof(pkt));   // Total packet length
    ip->id = htons(rand() & 0xFFFF);    // Random IP ID
    ip->saddr = src.s_addr;             // Source IP
    ip->daddr = dst.s_addr;             // Destination IP
    ip->check = 0;                      // Clear before computing checksum
    
    // Convert IPv4 header length from 32-bit words (IHL) to bytes for checksum calculation
    ip->check = checksum(ip, ip->ihl * 4);

    // Build TCP header
    tcp->source = htons(sp);            // Source port
    tcp->dest = htons(dp);              // Destination port
    tcp->doff = 5;                      // Data offset (5 * 4 = 20 bytes)
    tcp->rst = 1;                       // Set RST flag
    if (do_ack) tcp->ack = 1;           // Set ACK flag if requested
    tcp->seq = htonl(seq);              // Sequence number
    tcp->ack_seq = htonl(ack);          // Acknowledgment number
    tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr));
    
    // Send the RST packet
    struct sockaddr_in d = {.sin_family = AF_INET, .sin_addr = dst};
    sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&d, sizeof(d));
}

/**
 * Scan a single TCP port using SYN scan technique (stealth scan)
 * 
 * @param ss   Send socket (raw socket for sending)
 * @param rs   Receive socket (raw socket for receiving)
 * @param src  Source IP address (our IP)
 * @param dst  Destination IP address (target)
 * @param sp   Source port (our port)
 * @param p    Destination port (port to scan)
 * @return     1 if port is open, 0 if closed/filtered
 */
int scan_tcp(int ss, int rs, struct in_addr src, struct in_addr dst, uint16_t sp, uint16_t p) {
    // Allocate packet buffer: IP header + TCP header (no payload)
    unsigned char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
    struct iphdr *ip = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    uint32_t seq = rand();  // Random initial sequence number
    
    // Build IP header
    ip->ihl = 5;                        // Header length (5 * 4 = 20 bytes)
    ip->version = 4;                    // IPv4
    ip->ttl = 64;                       // Time to live
    ip->protocol = IPPROTO_TCP;         // TCP protocol
    ip->tot_len = htons(sizeof(pkt));   // Total packet length
    ip->id = htons(rand() & 0xFFFF);    // Random IP ID
    ip->saddr = src.s_addr;             // Source IP (our IP)
    ip->daddr = dst.s_addr;             // Destination IP (target)
    ip->check = ip_checksum(ip);        // Compute IP checksum
    
    // Build TCP SYN packet
    tcp->source = htons(sp);            // Our source port
    tcp->dest = htons(p);               // Target port
    tcp->seq = htonl(seq);              // Our sequence number
    tcp->doff = 5;                      // Data offset (20 bytes)
    tcp->syn = 1;                       // SYN flag (connection request)
    tcp->window = htons(65535);         // Maximum window size
    tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr));
    
    // Send the SYN packet
    struct sockaddr_in d = {.sin_family = AF_INET, .sin_addr = dst};
    if (sendto(ss, pkt, sizeof(pkt), 0, (struct sockaddr *)&d, sizeof(d)) < 0) return 0;
    
    // Wait for response using poll (non-blocking with timeout)
    struct pollfd pfd = {.fd = rs, .events = POLLIN};
    unsigned char buf[2048];
    int open = 0;
    
    // Poll for TCP_TIMEOUT_MS milliseconds
    if (poll(&pfd, 1, TCP_TIMEOUT_MS) > 0 && (pfd.revents & POLLIN)) {
        // Data is available to read
        ssize_t n = recvfrom(rs, buf, sizeof(buf), 0, NULL, NULL);
        
        if (n >= (ssize_t)sizeof(struct iphdr)) {
            struct iphdr *rip = (struct iphdr *)buf;
            int ihl = rip->ihl * 4;  // IP header length in bytes
            
            // Make sure we have enough data for TCP header
            if (n >= ihl + (ssize_t)sizeof(struct tcphdr) && rip->protocol == IPPROTO_TCP) {
                struct tcphdr *rtcp = (struct tcphdr *)(buf + ihl);
                
                // Verify this response is for our probe
                if (rip->saddr == dst.s_addr &&           // From our target
                    rip->daddr == src.s_addr &&           // To us
                    ntohs(rtcp->source) == p &&           // From the port we scanned
                    ntohs(rtcp->dest) == sp) {            // To our source port
                    
                    uint32_t pseq = ntohl(rtcp->seq);     // Their sequence number
                    uint32_t pack = ntohl(rtcp->ack_seq); // Their ack number
                    
                    // SYN+ACK means port is OPEN
                    if (rtcp->syn && rtcp->ack) {
                        open = 1;
                        // Send RST+ACK to close the connection politely
                        // seq = what they acked, ack = their seq+1
                        send_rst(ss, src, dst, sp, p, pack, pseq + 1, 1);
                    } 
                    // RST means port is CLOSED
                    else if (rtcp->rst) {
                        // Still send RST (assignment requirement: send RST either way)
                        send_rst(ss, src, dst, sp, p, pack, pseq, 1);
                    }
                }
            }
        }
    }
    
    // If timeout or no match: treat as closed/filtered
    // Still send a simple RST (assignment requirement)
    if (!open) send_rst(ss, src, dst, sp, p, seq + 1, 0, 0);
    
    return open;
}

int main(int argc, char **argv) {
    const char *host = NULL;
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "a:")) != -1) {
        if (opt == 'a') host = optarg;        // Target host
        else { 
            fprintf(stderr, "Usage: sudo %s -a <host>\n", argv[0]); 
            return 1; 
        }
    }
    
    // Validate required arguments
    if (!host) { 
        fprintf(stderr, "Usage: sudo %s -a <host>\n", argv[0]); 
        return 1; 
    }
    
    // Resolve hostname to IP
    struct in_addr dst;
    if (resolve_ipv4(host, &dst)) { 
        fprintf(stderr, "Error: cannot resolve '%s'\n", host); 
        return 1; 
    }
    
    // Seed random number generator (for sequence numbers and IDs)
    srand(time(NULL) ^ getpid());
    
    // Print scan info
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst, ip, sizeof(ip));
    printf("Scanning %s (%s) with TCP...\n", host, ip);
    
    // Get our local IP for routing to destination
    struct in_addr src;
    if (get_local_ip(dst, &src)) { 
        fprintf(stderr, "Error: cannot get local IP\n"); 
        return 1; 
    }
    
    // Create raw socket for sending (with IP_HDRINCL to build our own headers)
    int ss = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ss < 0) { 
        perror("socket"); 
        return 1; 
    }
    
    // Tell kernel we're providing our own IP headers
    int one = 1;
    if (setsockopt(ss, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt"); 
        close(ss); 
        return 1;
    }
    
    // Create raw socket for receiving TCP responses
    int rs = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rs < 0) { 
        perror("socket"); 
        close(ss); 
        return 1; 
    }
    
    // Use one source port for the whole scan (simplifies matching)
    uint16_t sp = 40000 + (getpid() % 20000);
    
    // Scan all ports from 1 to 65535
    for (int p = PORT_MIN; p <= PORT_MAX; p++) {
        // Scan the port
        if (scan_tcp(ss, rs, src, dst, sp, p)) {
            // Print if port is open
            printf("OPEN TCP %d\n", p);
            fflush(stdout);  // Immediate output
        }
        
        // Progress indicator every 2000 ports
        if (p % 2000 == 0) 
            fprintf(stderr, "Scanned %d/65535...\n", p);
    }
    
    // Clean up sockets
    close(rs);
    close(ss);
    
    printf("Scan complete.\n");
    return 0;
}