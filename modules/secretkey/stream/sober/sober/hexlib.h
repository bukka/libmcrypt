/* useful hex manipulation routine header */
/* Copyright C Qualcomm Inc 1997 */
/* %W% (AHAG) %E% */

extern int	nerrors;

int hexprint(const char *, unsigned char *, int n);
int hexread(unsigned char *, char *, int n);
int hexcheck(unsigned char *, char *, int n);
int hexbulk(unsigned char *, int n);
