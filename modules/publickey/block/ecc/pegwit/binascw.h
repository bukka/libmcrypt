int getLine(char *buffer, int buflen, char ** t, int addLF);
int putLine(char **buffer, char * t, int addCRLF);
int putLines(char **buffer, char * t, int addCRLF);
int flushArmour(FILE * stream, char **t_out, int nocrlf);
size_t freadPlus(void *ptr, size_t size, size_t n, FILE *stream, int binmode, char **t_inp);
size_t fwritePlus(const void *ptr, size_t size, size_t n, FILE *stream, int binmode, char ** t_out);
int fputcPlus(int c, FILE *stream, int binmode, char **t_out);
void init_binasc(void);
void burnBinasc(void);
