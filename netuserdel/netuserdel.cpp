#ifdef UNICODE
#define UNICODE
#endif
#include<windows.h>
#include<stdio.h>
#include<Shlobj.h>
#include<stdlib.h>
#include<lm.h>

#pragma comment(lib,"netapi32.lib")

int wmain(int argc, wchar_t* argv[])
{
	 /// <summary>
	 /// NetUserDel 删除用户API              
	 /// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserdel
	 /// </summary>

	 
	 /*
			NET_API_STATUS NET_API_FUNCTION NetUserDel(
				LPCWSTR servername,              常量字符串 指定DNS或者NetBIOS远程服务器的名称，NULL表示本地机器          
				LPCWSTR username                 指定要删除的用户账户
				);


			Return value:  如果函数执行成功，返回值为 NERR_Success
	 */

	 
	// 判断是否以管理员权限执行，否则无法删除用户
	BOOL IsAdmin = IsUserAnAdmin();                       // https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-isuseranadmin         
	if (!IsAdmin)
	{
		fwprintf(stderr, L"[-] Run as administrator level!\n");
		exit(EXIT_FAILURE);
	}

	if (argc != 2)
	{
		fwprintf(stderr, L"[-] Usage: %s username\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	DWORD dwError = 0;
	NET_API_STATUS nStatus;

	// 调用NetUserDel  Api
	nStatus = NetUserDel(NULL, argv[1]);
	if (nStatus == NERR_Success)
	{
		fwprintf(stderr, L"[+] User %s has been successfully deleted on localhost!\n", argv[1]);
	}
	else
	{
		fwprintf(stderr, L"[-] A System error has occurred: %d\n", nStatus);
		exit(EXIT_FAILURE);
	}
	return 0;
	 
}