#include <time.h>
#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv) {
	while (1) {
		printf("%ld\n", GetCurrentProcessId());
		Sleep(5000);
	}
}