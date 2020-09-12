#ifdef UNICODE
#define UNICODE
#endif
#include<windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<lm.h>
#include<assert.h>

#pragma comment(lib,"netapi32.lib")

int wmain(int argc, wchar_t* argv[])
{
	      /// <summary>
		  /// NetUserEnum 用户枚举Api  功能等效于 net user
	      /// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
		  ///
		  /// </summary>
		  
		  /*
				 NET_API_STATUS NET_API_FUNCTION NetUserEnum(
					LPCWSTR servername,						常量字符串 指定DNS或者NetBIOS远程服务器的名称，NULL表示本地机器
					DWORD   level,							指定数据的信息级别  0 1 2 3 10 11 20  USER_INFO_0 结构体
					DWORD   filter,							指定包含在枚举用户账户类型的值，0值表示包含所有正常用户，可信数据和机器账户数据
					LPBYTE  *bufptr,						指向接收数据缓冲的指针，数据的格式依赖于参数level的值
					DWORD   prefmaxlen,						优先考虑返回数据字节最大长度 如果指定了MAX_PREFERED_LENGTH，则分配所需数据大小的内存
					LPDWORD entriesread,					指向接收枚举元素账户的值
					LPDWORD totalentries,					指向一个值的指针，该值接收可以从当前恢复位置枚举的条目总数
					PDWORD  resume_handle					指向包含用于继续现有用户搜索的恢复句柄的值的指针
					);

				Note:
					The buffer for this data is allocated by the system and 
					the application must call the NetApiBufferFree function to free the allocated memory 
					when the data returned is no longer needed. 
					Note that you must free the buffer even if the NetUserEnum function fails with ERROR_MORE_DATA.

					如果数据的缓冲由系统分配，当返回数据不在需要时,应用程序必须调用NetApiBufferFree函数释放分配的内存.
					即使NetUserEnum函数以ERROR_MORE_DATA失败时，你必须释放缓冲。

				Return value: 函数执行成功返回 NERR_Success
		  */
	if (argc > 2)
	{
		fwprintf(stderr, L"[-] Usage: %s\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	// 设置结构体信息
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;                 // MAX_PREFERED_LENGTH = ((DWORD-1)
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;

	wprintf(L"[+] User account on localhost\n");

	//
	// Call the NetUserEnum function,specifying level 0   0表示 global user account 0
	//

	do   // start do
	{
		nStatus = NetUserEnum(
			(LPCWSTR)pszServerName,
			dwLevel,                 // USER_INFO_0 
			FILTER_NORMAL_ACCOUNT,   // global users
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,          // NetUserEnum api返回idwTotalCount=5   dwEntriesRead=5
			&dwTotalCount,
			&dwResumeHandle
		);

		// if call succeeds
 		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				// loop through the entries 循环遍历目录

				for (int i = 0; (i < dwEntriesRead); i++)
				{
					/*
							assert()  C++用法  作用是如果它的条件返回错误，则终止程序执行
							assert() 计算表达式，值为假，先向stderr打印一条出错信息，然后调用abort终止程序执行

							使用assert() 缺点: 频繁地调用会极大地影响程序的性能，增加额外的开销   #define NDEBUG 调试结束禁用assert调用
					*/

					assert(pTmpBuf != NULL);

					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "[-] An access violation has occurred\n");
						break;
					}

					// print the name of the user account

					wprintf(L"=> %s\n", pTmpBuf->usri0_name);

					pTmpBuf++;
					dwTotalCount++;
					
				}
			}
		}

		// otherwise,print the system error.
		else
		{
			fprintf(stderr,"[-] A system error has occurred: %d\n", nStatus);
		}

		// Free the allocated buffer
		if (pBuf != NULL)
		{

			// NetApiBufferFree 函数释放NetApiBufferAllocate函数申请的内存
			// https://docs.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
			// 

			/*
					NET_API_STATUS NET_API_FUNCTION NetApiBufferFree(
												_Frees_ptr_opt_ LPVOID Buffer
												);
					Buffer
					指向先前由另一个网络管理函数或者通过调用NetApiBufferAllocate函数分配的内存 返回的缓冲区的指针
			*/


			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}

	}

	// continue to call NetUserEnum while there are more entries.
	while (nStatus == ERROR_MORE_DATA);   // end do

	// 再次检测分配的内存
	if (pBuf != NULL)
	{
		NetApiBufferFree(pBuf);
	}

	// print the final count of users enumrated.
	fprintf(stderr, "Total of %d entries enumerated\n", dwTotalCount-5);

	return 0;
}