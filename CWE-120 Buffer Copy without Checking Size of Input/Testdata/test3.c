int main ()
{
    int a[] = {3, 2, 1};
    int* c = a;
    int b = a[1];
    b = *(c + 1); //hello
    return 0;
}