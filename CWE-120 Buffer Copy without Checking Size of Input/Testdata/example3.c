#include <stdio.h>
#include <string.h>
int main()
{
    /*Online examples found from https://fresh2refresh.com/c-programming/c-buffer-manipulation-function/
    and made to fit together in one main function*/

    //memcpy() example
    // define two identical arrays
    char str1[10] = "fresh";
    char str2[8];
    if (memcpy(str2,str1, strlen(str1)))
    {
        printf("Elements in str1 are copied to str2 .\n");
        printf("str1 = %s\nstr2 = %s \n", str1, str2);
    }
    else
        printf("Error while coping str1 into str2.\n");

    //memmove() example
    // define two identical arrays
    char str3[10] = "fresh";

    printf("str3 before memmove\n");
    printf("str3 = %s\n", str3);

    if (memmove(str3+2,str3, strlen(str3)))
    {
        printf("Elements in str3 are moved/overlapped on str3.\n");
        printf("str3 = %s \n", str3);
    }
    else
        printf("Error while coping str3 into str2.\n");

    //memset() example
    int i;
    /* allocate memory for array of 5 elements */
    char *a = (char *) malloc(5*sizeof(char));
    printf("Values before memset\n");
    for (i = 0; i < 5; ++i)
        printf("  a[%d] = %d ,", i,    a[i]);

    /* All elements are set to 3. It can be set to any value */
    memset(a, 3, 5*sizeof(char));
        printf("\nValues after memset\n");
    for (i = 0; i < 5; ++i)
        printf("  a[%d] = %d ,", i,    a[i]);
    // remove x from memory
    free(a);

    return 0;
}