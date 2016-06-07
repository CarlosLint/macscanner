/**************************************************
**                                               **
** macscanner.c                                  **
**                                               **
**   Scans the local (class C) subnet for known  **
** MAC addresses by sending UDP packets to each  **
** IP address passed by arguments and later      **
** showing all hosts found as MAC addresses.     **
**                                               **
**   MAC addresses are read from /etc/ethers if  **
** not passed via command line                   **
**                                               **
**************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

// ignore zero-length string warnings
#pragma GCC diagnostic ignored "-Wformat-zero-length"
//// standard plaintext output
#define INITIAL_STRING		""
#define OUTPUT_FORMAT_STRING 	"Found: %s\n"	// you can switch the output to whatever printf-compatible string you want
#define FINISH_STRING		""

//// Really simple HTML output
//#define INITIAL_STRING	"<html><title>Known MAC addresses</title><body>\n"
//#define OUTPUT_FORMAT_STRING	"%s<br>\n"
//#define FINISH_STRING		"</body></html>\n"

// we only scan one subnet (that's enough for all that I care)
#define DEFAULT_IP1	192
#define DEFAULT_IP2	168
#define DEFAULT_IP3	23
#define FIRST_IP 	1
#define LAST_IP 	254

// there goes all your mac addresses (be careful to finish it with a NULL ptr)
char *mac_addresses[8192] = { NULL };
// 4 octets of IP addr plus one additional for last IP
int ip[5] = { DEFAULT_IP1, DEFAULT_IP2, DEFAULT_IP3, FIRST_IP, LAST_IP };

// how many hosts are scanned per second is defined by HOSTS_PER_SECOND
#define HOSTS_PER_SECOND	25
#define UDP_PORT	8000
#define PAYLOAD		"payload goes here"

#define MACS (sizeof(mac_addresses)/sizeof(char *))


#define FINAL_ARP_WAIT	10	// how long to wait for arp replies -- don't set it too long or it might wipe the arp table


// murky argv parser, returns 0 if got no macs from command line arguments
int parse_argv(int argc, char **argv) {
  int dummy_ip;
  int i;

  if(argc==1) return(0);

  if(!strcmp(argv[1], "--help")) {
    printf("%s <first ip address> <last_ip_address> <mac_addr1> <mac_addr2> <mac_addr3>...\n", argv[0]);
    exit(1);
  }

  if(argc>1) sscanf(argv[1], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
  // the following is a weird yet necessary if/sscanf sequence.
  if(argc>2) if(sscanf(argv[2], "%d.%d.%d.%d", &dummy_ip, &dummy_ip, &dummy_ip, &ip[4])<4) sscanf(argv[2], "%d", &ip[4]);

  // limit the number of accepted mac addresses
  if(argc>(MACS+2)) argc=(MACS+2);

  bzero(mac_addresses, sizeof(mac_addresses));
  i=2;
  while(++i<argc) mac_addresses[i-3]=argv[i];
  mac_addresses[i-3]=NULL;		// finish the list with a Z

  return(i-3);
}



// allocate a buffer to store macs read from /etc/ethers, parse the file and fill it in
void retrieve_macs(void) {
  FILE *ethers=fopen("/etc/ethers", "r");
  unsigned int addr[6], i=0;
  char buffer[20];
  char *mac_storage=malloc(sizeof(buffer)*MACS);

  if(!ethers) return;
  if(!mac_storage) return;	// we'll never free() the mac_storage buffer, it's automagically free()d upon exit.

  while(!feof(ethers)) {
    if(fgets(buffer, sizeof(buffer), ethers)) {
      if(sscanf(buffer, "%x:%x:%x:%x:%x:%x", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5])>5) {
        snprintf(&mac_storage[i*sizeof(buffer)], sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        mac_addresses[i]=&mac_storage[i*sizeof(buffer)];
        i++;
      }
    }
  }
  mac_addresses[(i+1)*sizeof(buffer)]=NULL;
}




int main(int argc, char **argv) {
  int i, sockfd;
  char buffer[1024];
  FILE *popen_arp;
  char *scanchar;
  struct sockaddr_in sin;

  if(!parse_argv(argc, argv)) retrieve_macs();
  
  if(ip[3]>ip[4]) {	// the following is a xor swap
    ip[3]^=ip[4];
    ip[4]^=ip[3];
    ip[3]^=ip[4];
  }

  if((sockfd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))<0) {
    fprintf(stderr, "socket() error: %s\n", strerror(errno));
    return(-1);
  }
  bzero(&sin, sizeof(sin));

  sin.sin_family=AF_INET;
  sin.sin_port=htons(UDP_PORT);
  
  // try to reach all the hosts spawning a bunch of ping processes
  for(int i=ip[3];i<ip[4]+1;i++) {
    snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", ip[0], ip[1], ip[2], i);
    if(!inet_aton(buffer, &sin.sin_addr)) {
      fprintf(stderr, "Unable to send packet to %s.\n", buffer);
      break;
    }
    if(sendto(sockfd, PAYLOAD, strlen(PAYLOAD), 0, (struct sockaddr *)&sin, sizeof(sin))<0) {
      fprintf(stderr, "Unable to send packet to %s.\n", buffer);
      break;
    }

    if(HOSTS_PER_SECOND) usleep(1000000/HOSTS_PER_SECOND);	// wait for it..
    else usleep(200000);					// default = 200ms
  }
  
  usleep(5000000);	// let's wait 5 whole seconds for (arp replies) good measure

  // now query the system for all known mac addresses in REACHABLE state
  popen_arp=popen("ip -s neighbour list | grep REACHABLE | awk -e '{ print $5 }'", "re");


  printf(INITIAL_STRING);
  while(!feof(popen_arp)) {
    if(!fgets(buffer, sizeof(buffer), popen_arp)) break;
    // strips LF (and CR if we ever try to cross-compile it to Windows)

    scanchar=strchr(buffer, '\r');
    if(scanchar) *scanchar=0;
    scanchar=strchr(buffer, '\n');
    if(scanchar) *scanchar=0;

    // search for the mac addr at the mac_addresses array
    i=0;

    while(mac_addresses[i]) {
      if(!strcasecmp(mac_addresses[i], buffer)) printf(OUTPUT_FORMAT_STRING, buffer); 
      i++;
    }
  }
  printf(FINISH_STRING);

  return(0);
}

