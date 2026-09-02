# Compiler
CC = gcc

# Compiler flags:
# -Wall : enable all common warnings
# -O2   : optimization level 2
CFLAGS = -Wall -O2

# Targets (executables)
TARGETS = ping traceroute port_scanning

# Default target: build everything
all: $(TARGETS)

# Build ping from ping.c
ping: ping.c
	$(CC) $(CFLAGS) -o ping ping.c

# Build traceroute from traceroute.c
traceroute: traceroute.c
	$(CC) $(CFLAGS) -o traceroute traceroute.c

# Build port_scanning from port_scanning.c
# This exactly matches your working gcc command
port_scanning: port_scanning.c
	$(CC) $(CFLAGS) -o port_scanning port_scanning.c

# Clean compiled binaries
clean:
	rm -f $(TARGETS)