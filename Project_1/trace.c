#include "smartalloc.h"
#include "checksum.h"
#include <stdint.h>
#include <stdio.h>

void usage(char * argv)
{
   printf("Usage : %s PCAP_FILE\n", argv);
   exit(EXIT_FAILURE);
}

int main(int argc, char ** argv)
{
   if(argc != 2)
   {
      usage(argv[0]);
   }
   return EXIT_SUCCESS;
}
