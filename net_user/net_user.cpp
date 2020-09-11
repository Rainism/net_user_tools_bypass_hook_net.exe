#include<windows.h>
#include<lmaccess.h> 
#include<stdio.h>
#include<stdlib.h>
#include<lm.h>


#pragma comment(lib,"netapi32.lib")



int wmain(int argc, wchar_t * argv[])
{
	 /// <summary>
	 /// netusersetinfo   激活用户   =>  net user guest /active
	 /// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusersetinfo
	 /// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1008
	 /// </summary>
	
	 /*
			NET_API_STATUS NET_API_FUNCTION NetUserSetInfo(
				LPCWSTR servername,        常量字符串 指定DNS或者NetBIOS远程服务器的名称，NULL表示本地机器
				LPCWSTR username,		   指向常量字符串的指针 需要设置属性的用户
				DWORD   level,			   information level of the data.  1008 表示用户的熟悉  指向一个结构体 USER_INFO_1008
				LPBYTE  buf,			   指向指定数据的指针  数据的格式依赖于 level parameter
				LPDWORD parm_err           接收错误ERROR_INVALID_PARAMETER索引信息，NULL表示没有返回错误
				);

			NetUserSetInfo 成功后返回 NERR_Success 
	 */
	DWORD dwlevel = 1008;
	USER_INFO_1008 ui;
	NET_API_STATUS nStatus;

	if (argc != 2)
	{
		printf("Usage: %s username",argv[0]);
		exit(EXIT_FAILURE);
	}
	else
	{

	    ui.usri1008_flags = UF_LOCKOUT;            // 激活账户
		//ui.usri1008_flags = UF_ACCOUNTDISABLE;     // 锁定账户

		nStatus = NetUserSetInfo(NULL, argv[1], dwlevel, (LPBYTE)&ui, NULL);
		if (nStatus == NERR_Success)
		{
			printf("user account %s has been activated", argv[1]);
		}
		else
		{
			printf("A systm error has occurred: %d\n", nStatus);
		}
	}
	return 0;
}