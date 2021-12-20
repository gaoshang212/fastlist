#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <wctype.h>  
#include "cxxopts.hpp"


bool icompare_pred(unsigned char a, unsigned char b)
{
	return std::tolower(a) == std::tolower(b);
}

bool icasecompare(std::string const& a, std::string const& b)
{
	if (a.length() == b.length()) {
		return std::equal(b.begin(), b.end(),
			a.begin(), icompare_pred);
	}
	return false;
}

std::string stringToUTF8(const std::string& input)
{
	auto len = ::MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, NULL, 0);

	wchar_t* buffer = new wchar_t[len + 1];//一定要加1，不然会出现尾巴
	ZeroMemory(buffer, len * 2 + 2);

	::MultiByteToWideChar(CP_ACP, 0, input.c_str(), input.length(), buffer, len);

	int dstLen = ::WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, NULL, NULL, NULL);

	char* dstBuffer = new char[dstLen + 1];
	ZeroMemory(dstBuffer, dstLen + 1);

	::WideCharToMultiByte(CP_UTF8, 0, buffer, len, dstBuffer, dstLen, NULL, NULL);

	std::string retStr(dstBuffer);

	delete[]buffer;
	delete[]dstBuffer;

	buffer = NULL;
	dstBuffer = NULL;

	return retStr;
}
//

int main(int argc, char* argv[]) {

	cxxopts::Options options("faslist", "find process list.");

	options.allow_unrecognised_options()
		.add_options()
		("p,pid", "a process id", cxxopts::value<uint32_t>())
		("ppid", "a process id", cxxopts::value<uint32_t>())
		("n,name", "a process name", cxxopts::value<std::string>());

	auto result = options.parse(argc, argv);


	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 1;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap, &entry)) {
		CloseHandle(snap);
		return 1;
	}

	SetConsoleOutputCP(CP_UTF8);
	setvbuf(stdout, nullptr, _IONBF, 0);

	auto hasP = result.count("p");
	auto hasPPid = result.count("ppid");
	auto hasName = result.count("n");
	auto all = !hasP && !hasPPid && !hasName;

	do {
		//CW2A exe(entry.szExeFile, CP_UTF8);

		if (!all) {

			if (hasP && entry.th32ProcessID != result["p"].as<uint32_t>()) {
				continue;
			}
			else if (hasPPid && entry.th32ParentProcessID != result["ppid"].as<uint32_t>())
			{
				continue;
			}
			else if (hasName)
			{
				std::string filename(entry.szExeFile);
				if (!icasecompare(filename, result["n"].as<std::string>())) {
					continue;
				}
			}
		}

		std::cout
			<< entry.th32ProcessID << '\t'
			<< entry.th32ParentProcessID << '\t'
			<< stringToUTF8(entry.szExeFile) << '\n';

	} while (Process32Next(snap, &entry));

	CloseHandle(snap);
	return 0;
}