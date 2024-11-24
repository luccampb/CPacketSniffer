#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

//constants that correspond to certain necessary protocols/other numbers
#define ARP_ETHTYPE 0x0806
#define IP_ETHTYPE 0x0800
#define ARP_REPLY 0x0002
#define TCP_PROTOCOL 0x06
#define HTTP_PORT 0x50

//size of dynamic array
int size;
//number of arp replies
int arpcount;
//number of attempts to connect to bbc web server
int bbc;
//number of attempts to connect to google web server
int google;
//number of SYN packets sent
int numSyn;
//dynamic array which stores all ip addresses that sent us a SYN packet
uint32_t *ipArr;
//mutexes. can be initialised this way instead of using pthread_mutex_init()
pthread_mutex_t arrayLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arpLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t googleLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t bbcLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t synLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sizeLock = PTHREAD_MUTEX_INITIALIZER;

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  // TODO your part 2 code here
  //can convert the packet pointer to an ethernet header struct to access the values within
  struct ether_header *eth_header = (struct ether_header *) packet;
  //get the ether type to check if it is IP or ARP (converted to host byte ordere)
  uint16_t ethType = ntohs(eth_header->ether_type);
  //ether header is always 14 bytes long so the beginning of the next header is in the memory location 14 bytes after
  const unsigned char *next_header = (packet + ETH_HLEN);
  if(ethType == ARP_ETHTYPE) {
    //If it is an ARP packet then the header below the ethernet one is an ARP header
    struct ether_arp *eth_arp = (struct ether_arp *) next_header;
    //The value we care about must be accessed through a struct in a struct
    struct arphdr *ea = (struct arphdr *) &(eth_arp->ea_hdr);
    //convert the opcode to host byte order
    unsigned short int op = ntohs(ea->ar_op);
    //If opcode = 2 then it is an ARP reply so increment the number in the global variable
    if(op==ARP_REPLY) {
      pthread_mutex_lock(&arpLock);
      arpcount++;
      pthread_mutex_unlock(&arpLock);
    }
  } else  {
    //must go through ethernet and ip header to get to tcp header 
    //can cast this memory location to a struct pointer
    struct iphdr *iphead = (struct iphdr *) next_header;
    //used to get the length of the ip header as it is not constant
    u_int16_t ip_len = (iphead->ihl)*4;
    //get the protocol to see if it is TCP
    uint8_t protocol = iphead->protocol;
    if(protocol==TCP_PROTOCOL) {
      //tcp header is below the ip header
      const unsigned char *tcp_header = next_header + ip_len;
      struct tcphdr *tcphead = (struct tcphdr *) tcp_header;
      //Gets the length of the tcp header by adding 12 bytes to the pointer of the start of the header
      //This gets the data offset. Bitwise ANDing it with 240 returns only the first 4 ones in the byte obtained by the pointer
      //since the offset is only 4 bytes. It then right shifts the bits down (multiplies number by 2^-4) so that we get 0000xxxx instead of xxxx0000
      //This is because the offset part of tcphead did not seem to give the right number
      unsigned int tcp_len = ((*(tcp_header + 12)) & 0xF0) >> 4;
      tcp_len *= 4;
      //get the port number of the packet, we must check if it went through port 80 (which means it is an HTTP packet)
      unsigned short dport = ntohs(tcphead->th_dport);
      //gets the source ip address of the packet
      uint32_t ip_saddress = iphead->saddr;
      //Gets the TCP flags and compares them to just SYN
      unsigned char f = tcphead->th_flags;
      if(f == TH_SYN) {
        //Block of code contains lots of uses of global variables so lots of mutexes required
        pthread_mutex_lock(&synLock);
        int synSize = numSyn++;
        pthread_mutex_unlock(&synLock);
        pthread_mutex_lock(&sizeLock);
        int tempSize = size;        
        pthread_mutex_unlock(&sizeLock);
        pthread_mutex_lock(&arrayLock);
        //Check that our dynamic array is not about to go over the memory assigned to it
        //-20 so we resize the array just before we are required to to avoid certain strange parallelism conditions
        if(synSize >= tempSize-20) {
          //make the old array temporary in case the realloc does not work
          uint32_t *tmp = ipArr;
          tempSize *=2;
          ipArr = realloc(ipArr, tempSize * sizeof(uint32_t)); 
          //change the array to what it was before if the realloc is unsuccessful
          if (!ipArr) {
            write(STDOUT_FILENO, "Cannot reallocate memory", 24); 
            ipArr = tmp; 
            return;
          }
        }
        //store the ip address in the ip array
        ipArr[synSize] = ip_saddress;
        pthread_mutex_unlock(&arrayLock);
        pthread_mutex_lock(&sizeLock);
        //if tempSize changed then we need to change size as well so they match
        if(tempSize > size) {
          size *= 2;
        }        
        pthread_mutex_unlock(&sizeLock);
      }
      //If the port number is port 80 then it is a HTTP packet
      if(dport==HTTP_PORT) {
        //HTTP header can be found just below the tcp header
        const unsigned char *payload = (tcp_header + tcp_len);
        //Our two blacklisted servers
        const char comp1[] = "www.google.co.uk";
        const char comp2[] = "www.bbc.co.uk";
        //char to store result of strstr
        char *p = NULL;
        pthread_mutex_lock(&googleLock);
        //used to see which of the two blacklisted ones were modified
        int prevgoog = google;
        pthread_mutex_unlock(&googleLock);
        //returns a pointer to p of the first occurence of comp1 in payload. if comp1 is not in payload then returns null
        p = strstr(payload, comp1);        
        if (p!=NULL) {
          //it must have been a google packet
          pthread_mutex_lock(&googleLock);
          google+=1;
          pthread_mutex_unlock(&googleLock);
        } else {
          //otherwise check the other blacklisted site
          p = strstr(payload, comp2);
          if(p==NULL) {
            //If p is null then the request was not to a blacklisted site
            //and we know that the packet is not a SYN or ARP REPLY packet so we can just return at this point
            return;
          }
          pthread_mutex_lock(&bbcLock);
          bbc+=1;
          pthread_mutex_unlock(&bbcLock);
        }
        //get the destination address of the packet for our output
        uint32_t ip_daddress = iphead->daddr;
        //struct of in_addr required for inet_ntop
        struct in_addr *saddress = malloc(sizeof(struct in_addr));
        if(saddress == NULL) {
          perror("Unable to malloc");
        }
        saddress->s_addr = ip_saddress;
        struct in_addr *daddress = malloc(sizeof(struct in_addr));
        if(daddress == NULL) {
          perror("Unable to malloc");
        }
        daddress->s_addr = ip_daddress;
        //output buffers to store presentable ip addresses
        char readableSource[INET_ADDRSTRLEN];
        char readableDest[INET_ADDRSTRLEN];
        //converts 32 bit integers to presentable ip addresses
        inet_ntop(AF_INET, &saddress, readableSource, 32);
        inet_ntop(AF_INET, &daddress, readableDest, 32);
        //frees the malloc'd structs
        free(saddress);
        free(daddress);
        pthread_mutex_lock(&googleLock);
        //Output the violation detection as given in specification
        printf("\n==============================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP address: %s\n", readableSource); 
        //if google > prevgoog then google was increased by 1 in this function       
        if(prevgoog < google) {
          printf("Destination IP address: %s (google)\n", readableDest);
          printf("==============================");
        } else {
          printf("Destination IP address: %s (bbc)\n", readableDest);
          printf("==============================");
        }
        pthread_mutex_unlock(&googleLock);
      }
    }    
  }
}

//Called before packets begin being sniffed
void initAnalysis() {
  //initialised global variables
  size = 1000;
  arpcount = 0;
  bbc = 0;
  google = 0;
  numSyn = 0;
  ipArr = (uint32_t*) malloc(size * sizeof(uint32_t));
  if(ipArr == NULL) {
    perror("Unable to malloc");
  }
}

//Called when SIGINT is given
void interruptDump () {
  //pcap loop is broken and closed therefore printf should be safe to use in the interrupt output.
  //since there shouldnt be another printf holding a lock on stdout
  //This function is called after pthread_join, therefore all threads will have terminated (since pthread_join tells the program to wait until the completion of every thread)
  //Therefore all mutexes will be available for numSyn and ipArr and no other threads will ever execute so we do not need to lock them
  int unique = 1;
  //Calculate the number of unique ip addresses that sent a SYN packet
  for(int i = 1; i < numSyn; i++) {
    int j = 0;
    for(j = 0; j < i; j++) {
      if(ipArr[i]==ipArr[j])
        break;
    }
    if(i==j) {
      unique += 1;
    }  
  }
  if(numSyn==0) {
    unique = 0;
  }
  //The dynamic array was malloc'd so it must be freed
  free(ipArr);
  //Destroy the inited mutexes
  pthread_mutex_destroy(&arrayLock);
  pthread_mutex_destroy(&arpLock);
  pthread_mutex_destroy(&synLock);
  pthread_mutex_destroy(&googleLock);
  pthread_mutex_destroy(&bbcLock);
  //Print out the intrusion report
  printf("\nIntrusion Detection Report:\n%d SYN packets detected from %d different IPs (syn attack)\n", numSyn, unique);
  printf("%d ARP responses (cache poisoning)\n%d URL Blacklist violations (%d google and %d bbc)\n", arpcount, google + bbc, google, bbc);
}