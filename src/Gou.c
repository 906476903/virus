#include <stdio.h>

int main()
{
	char str[100] = "苟利国家生死以 岂能祸福趋避之\n";
	puts(str);
	int len = strlen(str);
	int i;
	for(i = 0; i < len; ++i)
	{
		printf("msg1[%d]=%d;\n", i, str[i]);
	}
	return 0;
}
