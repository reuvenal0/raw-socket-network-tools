#include <arpa/inet.h> // string <-> binary
#include <getopt.h> // get args (opt)
#include <errno.h> 
#include <netinet/in.h> // sockaddr_in, AF_INE methods
#include <netinet/ip_icmp.h> // struct icmphdr
#include <netinet/ip.h> // struct iphdr
#include <poll.h> // wait to event
#include <stdio.h> // stdio
#include <stdlib.h> // exit ect.
#include <signal.h> // SIGINT CTRL+C safe exit
#include <string.h> // string
#include <sys/socket.h> // socket
#include <time.h> // clock 
#include <unistd.h> // close, sleep, getpid.

#define ICMP_PAYLOAD_SIZE 56
#define ICMP_PACKET_SIZE (sizeof(struct icmphdr) + ICMP_PAYLOAD_SIZE) // == 64 == ICMP_PAYLOAD_SIZE(56) + ICMP_header (8)
#define RECV_BUF_SIZE 1500
#define TIMEOUT_MS 10000 // 10 sec

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

    // one’s complement:
	result = ~sum;
	return result;
}

/* Helper: convert (end-start) to milliseconds */
static double diff_ms(struct timespec start, struct timespec end) {
    long sec = end.tv_sec - start.tv_sec;
    long nsec = end.tv_nsec - start.tv_nsec;
    return (double)sec * 1000.0 + (double)nsec / 1e6;

    // nsec may become negative: this is still correct since the total time sum remains valid.
    // Some implementations normalize it, but for our use case this is usually fine.
}

// Stop global flag for Ctrl+C (SIGINT)
static volatile sig_atomic_t g_stop = 0;
// Signal handler (do not print here)
static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
}

// Build packet per-seq (checksum must be recomputed each time)
static void build_icmp_packet(unsigned char packet[ICMP_PACKET_SIZE],
                              unsigned short my_id,
                              unsigned short my_seq)
{
    memset(packet, 0, ICMP_PACKET_SIZE); // clean the memory 

    struct icmphdr *icmp = (struct icmphdr *)packet;
    // Set as ICMP echo request:
    icmp->type = ICMP_ECHO;
    icmp->code = 0;

    // Set the ID and seq (network byte order) of the ICMP packet
    icmp->un.echo.id = htons(my_id);
    icmp->un.echo.sequence = htons(my_seq);

    // Put just "junk" in the ICMP payload for us to send it..
    for (int i = 0; i < ICMP_PAYLOAD_SIZE; i++) {
        packet[sizeof(struct icmphdr) + i] = (unsigned char)('A' + (i % 26));
    }

    icmp->checksum = 0; // default val before calaulate (so we will get a real checksum)
    icmp->checksum = checksum(packet, ICMP_PACKET_SIZE); // calaulate checksum
}


int main(int argc, char **argv) {
    // First let's read command line args
    char *address = NULL; // Where to ping
    long count = -1; // How many pings (-1 = infinite)
    int flood = 0; // Flood mode on/off

    int opt;
    while ((opt = getopt(argc, argv, "a:c:f")) != -1) {
        switch (opt) {

            case 'a':
                address = optarg; // Save destination address
                break;

            case 'c': {
                // Convert count from string to number
                char *end = NULL;
                errno = 0;
                long value = strtol(optarg, &end, 10);

                // Make sure the number is valid and positive
                if (errno != 0 || end == optarg || *end != '\0' || value <= 0) {
                    fprintf(stderr, "Invalid value for -c: %s\n", optarg);
                    return 1;
                }

                count = value;
                break;
            }

            case 'f':
                flood = 1; // No delay between pings
                break;

            default:
                // Handle unknown flags - print ERR to stderr 
                fprintf(stderr, "Unknown option. Use -a <address> [-c <count>] [-f]\n");
                return 1;
        }
    }

    // The -a flag is needed
    if (address == NULL) {
        fprintf(stderr, "Error: -a <address> is required\n");
        return 1;
    }

    // Install SIGINT handler (Ctrl+C)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Prepare address and socket:
    struct sockaddr_in dest;
    // Clean the structure
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    // Convert IPv4 string into binary form
    if (inet_pton(AF_INET, address, &dest.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", address);
        return 1;
    }

    // Now let's create a raw socket for ICMP
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        fprintf(stderr, "Socket didnt run! make sure you use sudo!!!\n");
        return 1;
    }

    // set custom TTL to 64 as amit said in the lecture (the IP header is on the OS to build...)
    int ttl_value = 64;
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl_value, sizeof(ttl_value)) < 0) {
        perror("setsockopt IP_TTL");
        close(sock);
        return 1;
    }

    // Print that the socket is up and running:
    printf("Pinging %s with 64 bytes of data:\n", address);

    // Session statistics:
    long transmitted = 0;
    long received = 0;
    // RTT statistics
    double rtt_min = 0.0;
    double rtt_max = 0.0;
    double rtt_sum = 0.0;
    
    // Session timer for total time
    struct timespec session_start;
    clock_gettime(CLOCK_MONOTONIC, &session_start);

    unsigned short my_id = (unsigned short)(getpid() & 0xFFFF);
    unsigned short my_seq = 0;

    // Reusable buffers
    unsigned char packet[ICMP_PACKET_SIZE];
    unsigned char recvbuf[RECV_BUF_SIZE];

    // Main loop - send multiple pings
    while (!g_stop && (count == -1 || transmitted < count)) {

        // Build packet for this seq (checksum changes per seq)
        build_icmp_packet(packet, my_id, my_seq);

        // Start counting time for RTT
        struct timespec t_start, t_end;
        clock_gettime(CLOCK_MONOTONIC, &t_start);

        // Send the packet to the destination:
        ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                              (struct sockaddr *)&dest, sizeof(dest));
                              // Socket file descriptor – the socket used to send data
                              // Pointer to the buffer containing the data to send
                              // Number of bytes to send from the buffer
                              // Send flags (usually 0 for default behavior)
                              // Destination address (IP + port, cast to sockaddr)
                              // Size of the destination address structure
        if (sent < 0) {
            perror("sendto");
            break;
        }

        // We send one packet so transmitted is plus 1:
        transmitted++; 

        // Wait up to 10 seconds for a reply, using poll()
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd)); // Clear the struc
        pfd.fd = sock; // The socket we want to monitor
        pfd.events = POLLIN; // We only care about "data available to read"

        // Block until data arrives, timeout expires, or an error occurs
        int pr = poll(&pfd, 1, TIMEOUT_MS);

        if (pr == 0) {
            // No data arrived before the timeout
            printf("Request timeout for icmp_seq %u\n", my_seq);
            break; // Stop the loop (do not retry)
        }

        if (pr < 0) {
            if (errno == EINTR) {
                // poll() was interrupted by a signal, retry the loop
                continue;
            }
            // Unexpected poll error
            perror("poll");
            // Abort on real error
            break;
        }

        // Receive the raw IP packet (it contains IP header + ICMP message)
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from); // Size of the source address structure

        // Read data from the socket into recvbuf:
        ssize_t n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                             (struct sockaddr *)&from, &fromlen);

        if (n < 0) {
            if (errno == EINTR) {
                // recvfrom() was interrupted by a signal, retry
                continue;
            }
            // Real receive error
            perror("recvfrom");
            break; // Stop on failure
        }

        // Close the timmer
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        // Calculate the RTT in milliseconds
        double rtt = diff_ms(t_start, t_end);

        // Parse IP header to find TTL and ICMP header offset
        struct iphdr *ip = (struct iphdr *)recvbuf;
        int ip_header_len = ip->ihl * 4;
        int ttl = ip->ttl;

        // check that the reaceved data is valid
        if (n < ip_header_len + (ssize_t)sizeof(struct icmphdr)) {
            fprintf(stderr, "Received packet too short\n");
            // Treat as "not received", continue
            my_seq++;

            if (!flood && !g_stop) sleep(1);
            continue;
        }

        // Find and create the ICMP package
        struct icmphdr *ricmp = (struct icmphdr *)(recvbuf + ip_header_len);

        // Validate that this is our Echo Reply
        // Echo Reply type = ICMP_ECHOREPLY (0) AND same ID AND same sequence (using ntohs to convert for B-E to L-E)
        if (ricmp->type == ICMP_ECHOREPLY &&
            ntohs(ricmp->un.echo.id) == my_id &&
            ntohs(ricmp->un.echo.sequence) == my_seq) {

            received++;

            // Update RTT stats
            if (received == 1) {
                rtt_min = rtt_max = rtt;
            } else {
                if (rtt < rtt_min) rtt_min = rtt;
                if (rtt > rtt_max) rtt_max = rtt;
            }
            rtt_sum += rtt;

            // Convert the ip form binary to IP str:
            char from_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));

            // Print the <msg>: "64 bytes from X: icmp_seq=1 ttl=117 time=5.98ms"
            ssize_t icmp_bytes = n - ip_header_len;

            printf("%zd bytes from %s: icmp_seq=%u ttl=%d time=%.3fms\n", icmp_bytes, from_ip, my_seq, ttl, rtt);   
        }
        else {
        // Could be another ICMP message; for now just show a debug line
        printf("[debug] got ICMP type=%d code=%d (not our echo reply)\n",
               ricmp->type, ricmp->code);
        }

        my_seq++;

        // Flood mode means no sleep
        if (!flood && !g_stop) {
            sleep(1);
        }
    }

    // Print final ping statistics
    struct timespec session_end;
    clock_gettime(CLOCK_MONOTONIC, &session_end);   // Take end timestamp
    double total_ms = diff_ms(session_start, session_end); // Total session duration

    printf("\n--- %s ping statistics ---\n", address);
    printf("%ld packets transmitted, %ld received, ", transmitted, received);

    long lost = transmitted - received;  // Number of lost packets
    double loss_pct = 0.0;

    if (transmitted > 0) {
        // Calculate packet loss percentage
        loss_pct = (double)lost * 100.0 / (double)transmitted;
    }

    printf("%.1f%% packet loss, time %.0fms\n", loss_pct, total_ms);

    if (received > 0) {
        // Compute average RTT from successful replies
        double rtt_avg = rtt_sum / (double)received;
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
            rtt_min, rtt_avg, rtt_max);
    }

    close(sock); // Close the socket
    return 0; // Normal program exit
}