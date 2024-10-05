#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char* argv[])
{
	if(argc<2){
		printf("Unable to execute\n");
		exit(1);
	}
	// printf("double: %d\n", argc);
	unsigned long num = atoi(argv[argc-1]);
    if(argc==2) printf("%lu\n", 2*num);
	else if(argc>2){
		char* argv_new [argc];
		char temp[1000];
		temp[0]='.';
		temp[1]='/';
		strcpy(temp+2, argv[1]);
		int len = strlen(argv[1]);
		temp[2+len]='\0';
		argv_new[0] = temp;
		for (int i = 2; i < argc-1; i++) {
			argv_new[i - 1] = argv[i];
		}
		char str[1000]; 
		sprintf(str, "%lu", 2*num);
		argv_new[argc-2]=str;
		argv_new[argc-1]=NULL;
		// printf("%s", argv_new[0]);
		if(execvp(argv_new[0], (char * const *)argv_new)==-1){
			printf("Unable to execute\n");
			exit(1);
		};
	}
	return 0;
}

