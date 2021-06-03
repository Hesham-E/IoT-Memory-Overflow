int func (int x)
{

    int a = x + 1;
    long b = a;
    b = a + 1;
    b = 9223372036854775805 + 1 + 10;
    a = 1;

    return a;
}