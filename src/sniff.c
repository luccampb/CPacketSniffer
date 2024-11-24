#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>

#include "analysis.h"
#include "dispatch.h"

pcap_t *pcap_handle;

//Handler for keyboard interrupt
void sighandler(int num) {
  //SIGINT is a keyboard interrupt signal
  if (num == SIGINT) {
    //breaks the capturing loop and closes the handle
    pcap_breakloop(pcap_handle);
    pcap_close(pcap_handle);
    //calls the function in dispatch which will terminate threads and give the desired output
    sigDestroy();
    exit(0);
  }    
}

void handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *bytes) {
  int verbose = (int)*user;
  if (bytes == NULL) {
    // pcap_next can return null if no packet is seen within a timeout
    if (verbose) {
      printf("No packet received. %s\n", pcap_geterr((pcap_t*)bytes));
    }
  } else {
    // If verbose is set to 1, dump raw packet to terminal
    if (verbose) {
      dump(bytes, header->len);
    }
    // Dispatch packet for processing
    dispatch(header, bytes, verbose);
  }
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  //When the SIGINT signal is given, control transfers to the handler
  signal (SIGINT, sighandler);
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  //initialises threads in dispatch as well as mutexes
  initDispatch();
  struct pcap_pkthdr header;

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().

  //Gives pcap_loop the handle, the handler and the verbosity which is used as arguments in the handler function 
  pcap_loop(pcap_handle, 0, handler, (unsigned char *) &verbose);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    // if data_bytes is less than output_sz then output_bytes = data_bytes, otherwise its 20 (output_sz)
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}