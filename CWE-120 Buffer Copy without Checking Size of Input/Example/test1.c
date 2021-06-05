#include <stdlib.h>
#include <string.h>

double globalVar = 100.1;
int main ()
{
    int SIZE = 10;
    char str1[] = "Hello1";
    char str2[] = "Bye";
    char* str3 = "Pointer";
    char* str4 = &str2;
    char* str5;
    str5 = &str1;
    str5 = &str2[1];
    str5 = *str3;
    char str6[SIZE];
    char text[10] = "";
    //memset, memcpy, memmove, malloc, calloc, strcpy
    memmove(str2, str1, SIZE);
    strcpy(str2, str1);
    return 0;
}