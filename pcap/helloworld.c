#include <stdio.h>

int add_two_integer (int i1, int i2, int *i4)
{
	int i3 = 0;

	printf("DEBUG: add_two_integer: int1 = %d\n", i1);
	printf("DEBUG: add_two_integer: int2 = %d\n", i2);

	i3 = i1 + i2;

	//return i3;
	
	*i4 = i1 + i2;

	if (*i4 < 0 )	return 1;
	else		return 0;
}

int main()
{
	int a = 10;
	int b = -20;
	int c = 0;
	int d = 0;
	int e = 0;

	c = a + b;
	//d = add_two_integer(a, b);
	d = add_two_integer(a, b, &e);

	printf("HELLO WORLD\n");
	printf("a = %d\n", a);
	printf("b = %d\n", b);
	printf("c = %d\n", c);
	printf("d = %d\n", d);
	printf("e = %d\n", e);

	//return 0;
	return 1;
}
