#include <stdio.h>
#include <string.h>

static const char *sets[] =
{
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"0123456789",
	"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
};
static const unsigned setsize = sizeof(sets)/sizeof(sets[0]);

void print_charset(int flag)
{
	unsigned i;
	unsigned setlen = 0; // len. of merged set
	unsigned numsets = 0; // num. of sets used
	printf("\t{\"");
	const char *set, *p;
	for(i = 0; i < setsize; i++)
	{
		if(flag & (1 << i))
		{
			set = sets[i];
			for(p = set; *p; p++)
			{
				switch(*p)
				{
					case '\"':
					case '\\':
						printf("\\%c", *p);
						break;
					default:
						putchar(*p);
				}
			}
			setlen += strlen(set);
			numsets++;
		}
	}
	printf("\", %i, %i},\n", setlen, numsets);
}



int main(void)
{
	int i;
	int start = 0;
	int end = (1 << setsize) - 1;

	printf("typedef struct charset_s\n{\n\tconst char *value;\n\tunsigned length; // set length\n" \
		"\tunsigned numsets; // number of sets used\n} charset_t;\n\n");
	printf("static const charset_t cslist[] = \n{\n");
	for(i = start; i <= end; i++)
	{
		print_charset(i);
	}
	printf("};\n\nstatic const unsigned cslistsize = sizeof(cslist)/sizeof(cslist[0]); // = %i\n" \
		"#define CSLISTFLAG %i", i, end);

	return 0;
}