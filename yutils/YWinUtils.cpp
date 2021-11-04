#include "YWinUtils.h"
#include <windows.h>
#include <string>
#include <tchar.h>
#include "YCppDefer.hpp"

void AutoStart()
{
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) ///打开启动项
	{
		return;
	}
	defer(RegCloseKey(hKey););

	TCHAR strExeFullDir[MAX_PATH];
	GetModuleFileName(NULL, strExeFullDir, MAX_PATH);

	std::wstring FileName(strExeFullDir);
	FileName = FileName.substr(FileName.rfind(L"\\") + 1);
	FileName = FileName.substr(0, FileName.rfind(L"."));

	TCHAR strDir[MAX_PATH] = {};
	DWORD nLength = MAX_PATH;
	long result = RegGetValue(hKey, nullptr, FileName.c_str(), RRF_RT_REG_SZ, 0, strDir, &nLength);
	if (result != ERROR_SUCCESS || _tcscmp(strExeFullDir, strDir) != 0)
	{
		RegSetValueEx(hKey, FileName.c_str(), 0, REG_SZ, (LPBYTE)strExeFullDir, (lstrlen(strExeFullDir) + 1) * sizeof(TCHAR));
	}
}

void CanclePowerOn()
{
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
	{
		return;
	}
	defer(RegCloseKey(hKey););

	TCHAR strExeFullDir[MAX_PATH];
	GetModuleFileName(NULL, strExeFullDir, MAX_PATH);

	std::wstring FileName(strExeFullDir);
	FileName = FileName.substr(FileName.rfind(L"\\") + 1);
	FileName = FileName.substr(0, FileName.rfind(L"."));
	RegDeleteValue(hKey, FileName.c_str());
}