#define PRINTBYTE(buf, size, label)  		\
   	{ u32 _i; printf("%6s: ", label);	\
   	  for (_i=0; _i<size; _i++) {		\
     	    printf("%02x", (buf)[_i] & 0xFF); 	\
   	  } 					\
	  printf("\n"); 			\
	}
#define PRINTZ(z, label) 			\
   	{ printf("%6s:", label); 		\
   	  mpz_out_str (stdout, 16, z);		\
   	  printf("\n"); 			\
	}	
#define PRINTZ10(z, label) 			\
   	{ printf("%6s:", label); 		\
   	  mpz_out_str (stdout, 10, z);		\
   	  printf("\n"); 			\
	}	

#ifdef TEST_SPEED

#include "speed.h" 
#define SPEED(code, bits_per_iter, total_iter, label)			\
	{ double _time = 0; u32 _iter; 					\
	  for (_iter=0; _iter<total_iter; _iter++) {			\
	    speed_starttime();						\
	    code;							\
	    _time += speed_endtime();					\
          }								\
	  printf ("%s time: %10.9f secs ", label, _time/total_iter);	\
	  printf ("(%10.9f Mbits/sec).\n", 	 			\
	           total_iter*bits_per_iter/(1048576*_time));		\
	}
#endif
