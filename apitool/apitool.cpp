#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")
#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <windows.h> 
#include <lm.h>
#include <tchar.h>
#include <assert.h>

USER_INFO_1 ui;
DWORD dwLevel = 1;
DWORD dwError = 0;
NET_API_STATUS nStatus;


bool EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		//cout << "获取令牌句柄失败!" << endl;
		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		//cout << "获取Luid失败" << endl;
		__try {
			if (hToken) {
				CloseHandle(hToken);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {};
		return false;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		//cout << "修改特权不完全或失败!" << endl;
		__try {
			if (hToken) {
				CloseHandle(hToken);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {};
		return false;
	}
	else
	{
		//cout << "修改为system成功!" << endl;
		return true;
	}

}


void addUser(int argc, wchar_t* argv[]) {
	fwprintf(stderr, L"username:%s\npassword:%s\n", argv[2], argv[3]);
	ui.usri1_name = argv[2];
	ui.usri1_password = argv[3];
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_DONT_EXPIRE_PASSWD;
	ui.usri1_script_path = NULL;

	nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);
	if (nStatus == NERR_Success) {
		fwprintf(stderr, L"User %s has been successfully added\n", ui.usri1_name);
	}
	else {
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);
	}

	exit(1);
}

void delUser(int argc, wchar_t* argv[]) {

	nStatus = NetUserDel(NULL, argv[2]);
	if (nStatus == NERR_Success) {
		fwprintf(stderr, L"User %s has been successfully delete\n", argv[2]);
	}
	else {
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);
	}

	exit(1);
}

void changePass(int argc, wchar_t* argv[]) {

	DWORD dwLevel = 1003;
	USER_INFO_1003 ui_1003;
	NET_API_STATUS nStatus;
	LPWSTR wNewPassword;
	LPWSTR wComputerName;
	LPWSTR wUserName;

	wComputerName = NULL;
	wUserName = argv[2];
	wNewPassword = argv[3];

	ui_1003.usri1003_password = wNewPassword;

	nStatus = NetUserSetInfo(wComputerName, wUserName, dwLevel, (LPBYTE)&ui_1003, NULL);

	if (nStatus == NERR_Success)
		fwprintf(stderr, L"User %s's password has been successfully changed\n", argv[2]);
	else
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);

	exit(0);
}

void addGroup(int argc, wchar_t* argv[]) {
	fwprintf(stderr, L"username:%s\ngroup:%s\n", argv[2], argv[3]);

	const wchar_t* name;
	name = (const wchar_t*)argv[2];
	wchar_t lpszUser[30] = { 0 };
	wcscpy(lpszUser, name);
	LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
	localgroup_members.lgrmi3_domainandname = lpszUser;
	nStatus = NetLocalGroupAddMembers(NULL,        // NULL
		argv[3],					  // group name 
		3,                            // name 
		(LPBYTE)&localgroup_members,  // buffer 
		1);
	switch (nStatus)
	{
	case 0:
		printf("User successfully added to %ls group.\n", argv[3]);
		break;
	case ERROR_MEMBER_IN_ALIAS:
		printf("User already in %ls group.\n", argv[3]);
		nStatus = 0;
		break;
	default:
		printf("Error adding user to %ls group: %d\n", argv[3], nStatus);
		break;
	}

	exit(1);
}

void listUser(int argc, wchar_t* argv[]) {
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	nStatus = NetUserEnum(NULL,
		dwLevel,
		FILTER_NORMAL_ACCOUNT,
		(LPBYTE*)&pBuf,
		dwPrefMaxLen,
		&dwEntriesRead,
		&dwTotalEntries,
		&dwResumeHandle);

	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
	{
		if ((pTmpBuf = pBuf) != NULL)
		{

			for (i = 0; (i < dwEntriesRead); i++)
			{
				assert(pTmpBuf != NULL);
				if (pTmpBuf == NULL)
				{
					fwprintf(stderr, L"An access violation has occurred\n");
					break;
				}
				fwprintf(stderr, L"--- %s\r\n", pTmpBuf->usri0_name);
				pTmpBuf++;
			}
		}
	}

	exit(1);
}

void listGroup(int argc, wchar_t* argv[]) {
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	PDWORD_PTR dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	nStatus = NetLocalGroupEnum(NULL, dwLevel, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, dwResumeHandle);

	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
	{
		if ((pTmpBuf = pBuf) != NULL)
		{

			for (i = 0; (i < dwEntriesRead); i++)
			{
				assert(pTmpBuf != NULL);
				if (pTmpBuf == NULL)
				{
					fwprintf(stderr, L"An access violation has occurred\n");
					break;
				}
				fwprintf(stderr, L"--- %s\r\n", pTmpBuf->usri0_name);
				pTmpBuf++;
			}
		}
	}

	exit(1);
}

void printHelp() {
	TCHAR szPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szPath, MAX_PATH);
	//(_tcsrchr(szPath, _T('\\')))[1] = 0; //pathName

	wchar_t* programName = &(_tcsrchr(szPath, _T('\\')))[1];

	fwprintf(stderr, L"\
Name:\n\
  WinApi Tools by Mking\n\n\
\
Usage:\n\
  %ls [options] [arguments...]\n\n\
\
Options:\n\
  adduser     (eg: %ls adduser test 123456) \n\
  addgroup    (eg: %ls addgroup test administrators) \n\
  changepass  (eg: %ls changepass test test@123) \n\
  deluser     (eg: %ls deluser test) \n\
  listuser    (eg: %ls listuser) \n\
  listgroup   (eg: %ls listgroup) \n\
", programName, programName, programName, programName, programName, programName, programName);

	exit(1);
}

int wmain(int argc, wchar_t* argv[])
{
	EnableDebugPrivilege();
	
	if (argc == 4 && wcscmp(argv[1], TEXT("adduser")) == 0)
	{
		addUser(argc, argv);
	}

	else if (argc == 4 && wcscmp(argv[1], TEXT("addgroup")) == 0)
	{
		addGroup(argc, argv);
	}

	else if (argc == 4 && wcscmp(argv[1], TEXT("changepass")) == 0)
	{
		changePass(argc, argv);
	}

	else if (argc == 3 && wcscmp(argv[1], TEXT("deluser")) == 0)
	{
		delUser(argc, argv);
	}

	else if (argc == 2 && wcscmp(argv[1], TEXT("listuser")) == 0)
	{
		listUser(argc, argv);
	}

	else if (argc == 2 && wcscmp(argv[1], TEXT("listgroup")) == 0)
	{
		listGroup(argc, argv);
	}

	else {
		printHelp();
	}

	return 0;

}

