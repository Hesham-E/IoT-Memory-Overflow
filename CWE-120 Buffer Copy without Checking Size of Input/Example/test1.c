#include <stdio.h>
#include <string.h>

void manipulate_string(char* string);


int main ()
{
    //Taken from CWE 120 examples
    char last_name[20];
    printf ("Enter your last name: ");
    scanf ("%s", last_name);

    manipulate_string(last_name);

    char c = getchar();
    while (c != '\n' && c != EOF)
    {
        c = getchar();
    }
    
    char buf[24];
    printf("Please enter your name and press <Enter>\n");
    gets(buf);

    return 0;
}

void manipulate_string(char * string)
{
    char buf[24];
    strcpy(buf, string);
}