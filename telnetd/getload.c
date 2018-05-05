#include <stdio.h>
#ifndef __linux
#include <kvm.h>
#include <nlist.h>
#include <rpcsvc/rstat.h>
#endif
#include <fcntl.h>

#ifndef FSCALE
#  define FSHIFT  8               /* bits to right of fixed binary point */
#  define FSCALE  (1<<FSHIFT)
#endif /* FSCALE */

#define loaddouble(la) ((double)(la) / FSCALE)
#define X_AVENRUN                0

#ifndef __linux
kvm_t *kd;
#endif
struct nlist nlst[]= { 
  {"_avenrun"},                  /* 0 */
  {0}         
};

static int avenrun[3];
static int avenrun_offset=0;
static char loadstring[]="xx.xx, xx.xx, xx.xx           ";
static double load_average[3]={999,999,999};
static getkvmloadopened = 0;

#ifdef MAIN
main()
{
	double out_average[3];
	int loadlimit[3];
	double load[3];
	load[0] = 15; load[1] = 11; load[2]= 20;
	loadlimit[0] = 0; loadlimit[1] = 0; loadlimit[2];
	printf("load %s %4.2f %4.2f %4.2f\n",checkload(load,out_average)?"OK":"Overload",out_average[0],out_average[1],out_average[2]);
	printf("%s\n",bbscheckload(loadlimit));
}
#endif

rstatload( load )
double load[];
{
    struct statstime rs;
    rstat( "localhost", &rs );
    load[ 0 ] = rs.avenrun[ 0 ] / (double) (1 << 8);
    load[ 1 ] = rs.avenrun[ 1 ] / (double) (1 << 8);
    load[ 2 ] = rs.avenrun[ 2 ] / (double) (1 << 8);
}


checkload(load,load_avg)
double load[3];
double load_avg[3];
{
	int i;
	if (!getkvmloadopened) {
           getkvmloadopen();
	}
	if (getkvmloadopened)
	  getkvmload(load_avg);
	else
	  rstatload(load_avg);
	for (i=0;i<3;i++)
	  if (load_avg[i] > load[i])
		return 0;
        return 1;
}

getkvmloadopen()
{
	int i;
	getkvmloadopened = 0;
	if ((kd = (kvm_t*)kvm_open(NULL,NULL,NULL,O_RDONLY,"load"))==NULL) {
		perror("kvmopen");
		return(-1);
	}
	if (avenrun_offset ==0) {
	  if ((i = kvm_nlist(kd,nlst)) < 0) 
	  {
		perror("kvm_nlist");
		return(-1);
	  }
	  avenrun_offset = nlst[X_AVENRUN].n_value;
	}
	getkvmloadopened = 1;
	return 0;
}

getkvmloadclose()
{
       if (getkvmloadopened) 
	  kvm_close(kd);
}

getkvmload(load_avg)
double load_avg[3];
{
	register int i;

        /* get load average array */
        (void) getkval (avenrun_offset, (int *) avenrun, sizeof (avenrun), "avenrun");
	for (i=0;i<3;i++)
  	   load_avg[i] = loaddouble(avenrun[i]);
}

extern char *sys_errlist[];
extern int errno;

getkval(offset, ptr, size, refstr)

unsigned long offset;
int *ptr;
int size;
char *refstr;

{
    if (kvm_read(kd, offset, ptr, size) != size)
    {
	if (*refstr == '!')
	{
	    return(0);
	}
	else
	{
	    fprintf(stderr, "kvm_read for %s: %s\n",
		refstr, sys_errlist[errno]);
            return(-1);
	    /*NOTREACHED*/
	}
    }
    return(1);
}
    
/*
      in.telnetd-15-16-17
      in.telnetd-10-15
      in.telnetd-10
*/

char *bbscheckload(loadlimit)
int loadlimit[];
{
	int i,j;
	char *p;
	double out_average[3];

	for (i=0;i<3;i++) { 
	   out_average[i]=0;
	   if (loadlimit[i] != 0)
	      load_average[i]= loadlimit[i];
        }
	if (! checkload(load_average,out_average)) {
	   return NULL;
	}
	sprintf(loadstring,"%4.2f, %4.2f, %4.2f",out_average[0],out_average[1],out_average[2]); 
	return loadstring;
}
