#include "YConsole.h"

YConsole::YConsole()
{
	AllocConsole();

	freopen("conin$", "r+t", stdin);

	freopen("conout$", "w+t", stdout);

	freopen("conout$", "w+t", stderr);
}

YConsole::~YConsole()
{
	fclose(stderr);

	fclose(stdout);

	fclose(stdin);

	FreeConsole();
}