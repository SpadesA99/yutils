#include "YFileUtils.h"
#include <windows.h>

bool YFileUtils::ForceDelFile(std::string path)
{
	char temp_path[MAX_PATH]{ 0 }, target_name[MAX_PATH]{ 0 };

	GetTempPathA(MAX_PATH, temp_path);
	GetTempFileNameA(temp_path, "edgo", 0, target_name);

	if (!MoveFileExA(path.c_str(), target_name, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
	{
		return false;
	}
	if (!MoveFileExA(target_name, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
	{
		return false;
	}
	return true;
}

std::string YFileUtils::get_current_dir()
{
	std::string path(MAX_PATH, 0);
	GetModuleFileNameA(nullptr, path.data(), MAX_PATH);
	return path.substr(0, path.rfind("\\"));
}

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
