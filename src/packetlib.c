#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/bpf.h>
#include <net/if.h>

#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include <unistd.h>
#include <errno.h>
#include <unistd.h>

#include "packetlib.h"

//Compile into Julia-ccall-able lib with the line below:
//gcc -Wall -shared -o packetlib.so -lgsl -lgslcblas -lm -fPIC packetlib.c

int send_l(char sb[], int len, int l2, int count, float delay, char iface[]){
	int a = bpf_open(iface);
	if(a==-1){
		return 0;
	}
	int b = 0;
	if(l2){
		b = l2_prepare(a, 3);
	}else{
		b = l3_prepare(a, 3);
	}
	if(b==-1){
		return 0;
	}
	int sent_bytes;
	if(count==0){
		for(;;){
			sent_bytes = write( a, sb, len );
			sleep(delay);
		}
	}else{
		for(int i=0; i<count; i++){
			sent_bytes = write( a, sb, len );
			sleep(delay);
		}
	}
	close(a);
	return sent_bytes;
}

int bpf_open(const char* interface){
    int bpf = -1;
    char buf[ 11 ] = { 0 };
    for( int i = 0; i < 256; i++ ){
	  sprintf( buf, "/dev/bpf%i", i );
      bpf = open( buf, O_RDWR );
      if( bpf != -1 ){
          break;
      }
    }
    if( bpf == -1 )
      {
        fprintf( stderr,"ERROR: Could not open BPF device (more than 256? errno = %i)\n", errno );
        return( -1 );
    }

    struct ifreq bound_if;
    strcpy( bound_if.ifr_name, interface );
    if( ioctl( bpf, BIOCSETIF, &bound_if ) < 0 )
      {
        fprintf( stderr, "ERROR: BIOCSETIF failed with errno = %i\n", errno );
        return( -1 );
      }
    else
    return bpf;
}

int l2_prepare( int bpf, unsigned int timeout )
{
  	int buf_len = 1;
	if( bpf == -1 ){
		fprintf( stderr, "ERROR: bpf is -1. What the hell?\n" );
	  	return( -1 );
	}
	if( ioctl( bpf, BIOCIMMEDIATE, &buf_len ) == -1 ){
	  	fprintf( stderr, "ERROR: BIOCIMMEDIATE failed with errno = %i\n", errno );
	  	return( -1 );
	}
	if( ioctl( bpf, BIOCGBLEN, &buf_len ) == -1 ){
	  	fprintf( stderr, "ERROR: BIOCGBLEN failed with errno = %i\n", errno );
	  	return( -1 );
	}
	if( ioctl( bpf, BIOCPROMISC, &buf_len ) == -1 ){
		fprintf( stderr, "ERROR: BIOCPROMISC failed with errno = %i\n", errno );
		return( -1 );
 	}
  	if( ioctl( bpf, BIOCSHDRCMPLT, &buf_len ) == -1 ){
		fprintf( stderr, "ERROR: BIOCSHDRCMPLT failed with errno = %i\n", errno );
		return( -1 );
 	}
  	struct timeval tv_timeout;
  	tv_timeout.tv_sec = timeout;
  	tv_timeout.tv_usec = 0;
  	if( ioctl( bpf, BIOCSRTIMEOUT, &tv_timeout ) == -1 ){
      fprintf( stderr, "ERROR: BIOCGRTIMEOUT failed with errno = %i\n", errno );
      return( -1 );
    }
  	return( buf_len );
}

int l3_prepare( int bpf, unsigned int timeout )
{
  	int buf_len = 1;
	if( bpf == -1 ){
		fprintf( stderr, "ERROR: bpf is -1. What the hell?\n" );
	  	return( -1 );
	}
	if( ioctl( bpf, BIOCIMMEDIATE, &buf_len ) == -1 ){
	  	fprintf( stderr, "ERROR: BIOCIMMEDIATE failed with errno = %i\n", errno );
	  	return( -1 );
	}
	if( ioctl( bpf, BIOCGBLEN, &buf_len ) == -1 ){
	  	fprintf( stderr, "ERROR: BIOCGBLEN failed with errno = %i\n", errno );
	  	return( -1 );
	}
	if( ioctl( bpf, BIOCPROMISC, &buf_len ) == -1 ){
		fprintf( stderr, "ERROR: BIOCPROMISC failed with errno = %i\n", errno );
		return( -1 );
 	}
  	struct timeval tv_timeout;
  	tv_timeout.tv_sec = timeout;
  	tv_timeout.tv_usec = 0;
  	if( ioctl( bpf, BIOCSRTIMEOUT, &tv_timeout ) == -1 ){
      fprintf( stderr, "ERROR: BIOCGRTIMEOUT failed with errno = %i\n", errno );
      return( -1 );
    }
  	return( buf_len );
}
