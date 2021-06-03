int func ()
{
    int a = 1;
    a += 2147483649;

    unsigned long b = 18446744073709551615;

    b = b + 1;
    b++;
    --b;
    unsigned short c = 1;
    short o = 1;
    unsigned long d = 10;
    unsigned char z = 'a';
    d -= 2;
    return 0;
}