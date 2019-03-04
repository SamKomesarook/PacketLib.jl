#ifndef PACKETLIB_ETH
#define PACKETLIB_ETH

struct ethernet_frame
{
  unsigned char dest_addr[ 6 ];
  unsigned char src_addr[ 6 ];
  unsigned short int type;
};


int send_l(char sb[], int len, int l2, int count, float delay, char iface[]);
int bpf_open( const char* interface );
int l2_prepare( int bpf, unsigned int timeout );
int l3_prepare( int bpf, unsigned int timeout );

#endif
