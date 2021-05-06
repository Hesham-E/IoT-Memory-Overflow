#include <stdio.h>
#include <string.h>

void manipulate_string(char* string);


int main ()
{
    //similar to exampel1.c but testing spaces
    char buf[10];
    
    printf("Enter a phrase: ");
    scanf ( "%s", buf);
    
    char c = getchar();
    while (c != '\n' && c != EOF)
    {
        c = getchar();
    }

    manipulate_string(buf);

    printf("Please enter your name and press <Enter>\n");
    gets ( buf );

    return 0;
}

void manipulate_string(char * string)
{
    char buf[5];
    strcpy ( buf , string);
}