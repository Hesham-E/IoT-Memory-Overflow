int func ()
{
    int c;
    c = bar();
    int d = bar();
    return c;
}

int bar ()
{
    int x = 1;
    int y = 1;
    return x + y;
}