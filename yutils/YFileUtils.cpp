#include "YFileUtils.h"
#include <windows.h>

void YFileUtils::YMenuFile(std::string path, std::function<bool(std::string)> dir_callback, std::function<bool(std::string)>file_callback)
{
	WIN32_FIND_DATAA pNextInfo;
	std::string buffer = path + "\\*.*";
	auto hFile = FindFirstFileA(buffer.c_str(), &pNextInfo);
	if (hFile)
	{
		do
		{
			if (pNextInfo.cFileName[0] == '.') {
				continue;
			}
			if (pNextInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				YMenuFile(path + "\\" + pNextInfo.cFileName, dir_callback, file_callback);
				dir_callback(path + "\\" + pNextInfo.cFileName);
			}
			else {
				file_callback(path + "\\" + pNextInfo.cFileName);
			}
		} while (FindNextFileA(hFile, &pNextInfo));
	}
}
