#pragma once
#include <string>
#include <sstream>
#include <regex>
#include <memory>
#include <windows.h>
#include "YCppDefer.hpp"

template<class out_type, class in_value>
static out_type convert(const in_value& t)
{
	std::stringstream stream;
	stream.clear();
	stream.str("");
	stream << t;
	out_type result;
	stream >> result;
	return result;
}

//template <typename... Args>
//static std::string format(_In_z_ _Printf_format_string_ char const* const fmt, Args... args) {
//	try
//	{
//		auto size = snprintf(nullptr, 0, fmt, args...);
//		if (size <= 0) {
//			return "";
//		}
//		size += 1;
//		auto formatted = new char[size] {0};
//		defer(if (formatted) {
//			delete[]formatted; formatted = nullptr;
//		});
//		sprintf_s(formatted, size, fmt, args...);
//		return formatted;
//	}
//	catch (...)
//	{
//		return "";
//	}
//}

static std::string decodeURIComponent(std::string encoded) {
	std::string decoded = encoded;
	std::smatch sm;
	std::string haystack;

	int dynamicLength = decoded.size() - 2;

	if (decoded.size() < 3) return decoded;

	for (int i = 0; i < dynamicLength; i++)
	{
		haystack = decoded.substr(i, 3);

		if (std::regex_match(haystack, sm, std::regex("%[0-9A-F]{2}")))
		{
			haystack = haystack.replace(0, 1, "0x");
			std::string rc = { (char)std::stoi(haystack, nullptr, 16) };
			decoded = decoded.replace(decoded.begin() + i, decoded.begin() + i + 3, rc);
		}

		dynamicLength = decoded.size() - 2;
	}

	return decoded;
}

#define new_str(_name,_len,_type) std::shared_ptr<_type[]> ##_name(new _type[_len + 2]); RtlZeroMemory(##_name.get(), _len + 2);

static std::wstring UTF8ToUnicode(const char* str)
{
	std::wstring res;
	auto len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	new_str(result, len, wchar_t);
	MultiByteToWideChar(CP_UTF8, 0, str, -1, result.get(), len);
	res = result.get();
	return res;
}

static std::string UnicodeToUTF8(const wchar_t* str)
{
	std::string res;
	auto len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
	new_str(result, len, char);
	WideCharToMultiByte(CP_UTF8, 0, str, -1, result.get(), len, NULL, NULL);
	res = result.get();
	return res;
}

static std::wstring ANSIToUnicode(const char* str)
{
	std::wstring res;
	auto len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	res.resize(len, 0);
	MultiByteToWideChar(CP_ACP, 0, str, -1, res.data(), len);
	return res;
}

static std::string UnicodeToANSI(const wchar_t* str)
{
	std::string res;
	auto len = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);
	new_str(result, len, char);
	WideCharToMultiByte(CP_ACP, 0, str, -1, result.get(), len, NULL, NULL);
	res = result.get();
	return res;
}

static std::string ANSIToUTF8(const char* str)
{
	return UnicodeToUTF8(ANSIToUnicode(str).c_str());
}

static std::string UTF8ToANSI(const char* str)
{
	return UnicodeToANSI(UTF8ToUnicode(str).c_str());
}