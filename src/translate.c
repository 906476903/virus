#include <stdio.h>

char str[100];

int main()
{
	char str1[100], str2[100];
		
	int j;
	int count = 0;
	while(scanf("%s", str) == 1)
	{
		if(strlen(str) == 2)
		{
			for(j = 0; j < 2; ++j)
				str1[j] = str[j];
			printf("0x%s\n", str1);
			count += 1;
		}
		else
		{
			for(j = 0; j < 2; ++j)
				str1[j] = str[j], str2[j] = str[j + 2];
			str1[2] = str2[2] = 0;
			printf("0x%s, 0x%s, \n", str1, str2);
			count += 2;
		}
	}
	fprintf(stderr, "code length %d\n", count);
	return 0;
}
