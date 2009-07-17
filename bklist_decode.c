#include <stdio.h>
#include <string.h>
long int strtoln(char *nptr, char **endptr, int base, int len);

main()
{
    char ftemp[1024];
    int i;
    while (fgets(ftemp, 1024, stdin) > 0)
	for (i = 0; i < 1024 && ftemp[i] != 0; i++)
	    if (ftemp[i] == '\\' && i < 1023 - 3) {
		putchar((char) strtoln(ftemp + ++i, NULL, 8, 3));
		i += 2;
	    }
	    else if (ftemp[i] == '\n')
		putchar(0);
	    else
		putchar((char) ftemp[i]);
	
}

long int strtoln(char *nptr, char **endptr, int base, int len)
{
    char scratch[20];
    strncpy(scratch, nptr, len);
    scratch[len] = (char) 0;
    return(strtol((scratch), endptr, base));
}
