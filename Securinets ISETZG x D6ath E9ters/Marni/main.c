#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup(){
	setbuf(stdin,0);
	setbuf(stdout,0);
	setbuf(stderr,0);
}

void iset(){
	printf("you did it\n");
	system("/bin/sh");
}

void vuln(){
	char buffer[16];
	printf("welcome to iset zaghouan and it's CTF , try to understand what i'm doing here\n");
	printf("this is something that might help you: %p\n",iset);
	read(0,buffer,0x200);
}

int main(int argc, char* argv[]){
	setup(); // don't mind this 
	vuln();
	return 0;
}
