#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char buf[10];

    printf("Please enter any random phrase");
    gets(buf);

    char first3[3];
    char first2[2];

    memmove(first3, buf, 3);
    memmove(first2, buf, 3);

    printf("The first two characters are \"%s\"", first2);
    printf("The first three characters are \"%s\"", first3);

    return 0;
}