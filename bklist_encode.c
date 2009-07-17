#include <stdio.h>
main(int argc, char **argv)
{
    unsigned char ftemp[8193];
    int i, j;
    int inchar;
    int fieldcount;

    while (1) {
        fieldcount = 0;
	i = 0;
        while ((inchar = getchar()) != EOF && inchar != 0 && i < 8192) {
            ftemp[i] = inchar;
	    i++;
	}
        ftemp[i] = 0;
        if (inchar == EOF)
            break;
top:
        for (j = 0; ftemp[j] != 0; j++) {
            if (fieldcount < 11)
                putchar(ftemp[j]);
            else {
                if (ftemp[j] == 92)
                    printf("\\%3.3o", (unsigned int) 92);
                else if (ftemp[j] > 32 && ftemp[j] < 127)
                    putchar(ftemp[j]);
                else
                    printf("\\%3.3o", (unsigned int) (ftemp[j]));
            }
            if (ftemp[j] == '\t' && fieldcount < 11)
                fieldcount++;
        }
	fieldcount++;
	if (strncmp(ftemp, "l\t", 2) == 0 && fieldcount == 12) {
	    printf("\t");
	    i = 0;
	    while ((inchar = getchar()) != EOF && inchar != 0 && i < 8192) {
		ftemp[i] = inchar;
		i++;
	    }
            ftemp[i] = 0;
	    goto top;
	}

	putchar('\n');
    }
}
