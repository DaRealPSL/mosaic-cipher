#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>


void remove_trailing_newline(char *str){
	if(!str) return;
	size_t len = strlen(str);
	if(len > 0 && str[len - 1] == '\n'){
		str[len - 1] = '\0';
	}
}

void str_to_lower(char *str){
	if(!str) return;
	for(; *str; ++str){
		*str = (char)tolower(*str);
	}
}

int safe_read_line(char *buffer, size_t size){
	if(!fgets(buffer, (int)size, stdin)){
		return 0; //EOF or error
	}
	remove_trailing_newline(buffer);
	return 1;
}

void press_enter_to_continue(void){
	printf("\nPress ENTER to continue...");
	int c;
	while((c = getchar()) != '\n' && c != EOF){} // flush
}