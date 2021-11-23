#pragma once
#include <string>
#include <functional>

class YFileUtils
{

public:
	YFileUtils() {};
	~YFileUtils() {};
public:
	static bool ForceDelFile(std::string path);

	static std::string get_current_dir();

	static void YMenuFile(std::string path, std::function<bool(std::string)> dir_callback, std::function<bool(std::string)>file_callback);
};

