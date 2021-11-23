#pragma once
#include <string>
#include <functional>

class YFileUtils
{
	void YMenuFile(std::string path, std::function<bool(std::string)> dir_callback, std::function<bool(std::string)>file_callback);
};

