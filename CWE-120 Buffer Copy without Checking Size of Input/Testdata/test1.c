#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void flushInput();

int main ()
{
    const int SIZE = 10;
    int shift;
    char input[SIZE];
    char shiftedInput[SIZE - 1];

    printf("\nPlease enter a number for the Caesar shift: ");
    scanf("%d", &shift);
    flushInput();
    printf("\nPlease enter a phrase for the Caesar shift: ");
    scanf("%s", input);
    flushInput();

    strcpy(shiftedInput, input);
    for (int i = 0; i < SIZE - 1; i++)
    {
        shiftedInput[i] = shiftedInput[i] + shift;
    }

    printf("\nThe recieved input was \"%s\"", input);
    strcpy(input, shiftedInput);
    printf("\nThe Caesar shift is now \"%s\"", input);

    return 0;
}

void flushInput()
{
    char c;
    while((c = getchar()) != '\n' && c != EOF)
    {

    }
}