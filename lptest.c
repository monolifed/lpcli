/* HGvqQQSDvF7YlA2S */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lp.h"

int readArgs(int argv, const char **args, lp_opts *opts)
{

	lp_defaultopts(opts);
	
	char pass[1024];
	/* parsing goes here */
	if (argv < 4)
	{
		printf("%s <site> <login> [pass] [options]\n", args[0]);
		exit(1);
	}
	snprintf(pass, sizeof pass, "%s", args[3]);
	
	opts->flags = LP_CSF_ALPHANUMERIC;
	/* end of parsing */
	
	return 0;
}





int main(int argc, const char **argv)
{
	lp_opts opts;
	readArgs(argc, argv, &opts);
	
	char genpass[opts.length + 1];
	lp_generate(argv[1], argv[2], argv[3], &opts, genpass, sizeof genpass);
	printf("%s\n", genpass);
	return 0;
}