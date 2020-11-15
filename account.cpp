#include "account.h"
#include <io.h>
#include <stdio.h>
#include <Windows.h>
#include <conio.h>


struct info {
	char name[100];
	char username[100];
	char password[100];
} infos[50];
int info_len = 0;

char* getBuff(char* from, char* to, int max) {
	while ((*from == '\r' || *from == '\n') && *from != '\0') from++;//Ìø¹ý»»ÐÐ
	if (*from == '\0') return NULL;
	for (int i = 0; i < max; i++) {
		*to = *from;
		from++;
		to++;
		if (*from == '\r' || *from == '\n' || *from == '\0') {
			break;
		}
	}
	*to = '\0';
	return from;
}

void SendUnicode(wchar_t data)
{
	INPUT input[2];
	memset(input, 0, 2 * sizeof(INPUT));

	input[0].type = INPUT_KEYBOARD;
	input[0].ki.wVk = 0;
	input[0].ki.wScan = data;
	input[0].ki.dwFlags = 0x4;//KEYEVENTF_UNICODE;

	input[1].type = INPUT_KEYBOARD;
	input[1].ki.wVk = 0;
	input[1].ki.wScan = data;
	input[1].ki.dwFlags = KEYEVENTF_KEYUP | 0x4;//KEYEVENTF_UNICODE;

	SendInput(2, input, sizeof(INPUT));
}
void sendstr(char* data) {
	WCHAR Temp[100] = { 0 };
	int len = strlen(data);
	//mbstowcs(Temp, data, len);
	MultiByteToWideChar(CP_ACP, MB_COMPOSITE, data, -1, Temp, 100);
	for (int i = 0; i < len; i++) {
		SendUnicode(Temp[i]);
	}
}

void LoadAccount() {
	if (_access("C://TroveAccount.txt", 0) == 0) {
		FILE* f = fopen("C://TroveAccount.txt", "rb");
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		printf("file size is %d\n", fsize);
		char* buff = (char*)malloc((fsize + 1) * sizeof(char));
		buff[fsize] = '\0';
		fseek(f, 0, SEEK_SET);
		fread(buff, fsize * sizeof(char), 1, f);
		//printf("the body of file is:\n%s\n", buff);
		char* p = buff;
		while (true)
		{
			p = getBuff(p, infos[info_len].name, 99);
			if (p == NULL) break;
			p = getBuff(p, infos[info_len].username, 99);
			if (p == NULL) break;
			p = getBuff(p, infos[info_len].password, 99);
			if (p == NULL) break;
			info_len++;
			if (info_len == 50) {
				printf("tai duo le\n");
			}
		}
		//fgets()
		fclose(f);
		free(buff);
	}
	else {
		printf("file not find");
	}
}

void ShowAccount() {
	char d = '1';
	for (int i = 0; i < info_len; i++) {
		printf("%c: %s\t", d, infos[i].name);
		if (d == '9') d = '0';
		else if (d == '0') d = 'a';
		else if (d == 'z') d = 'A';
		else d++;
	}
	printf("\n");
}

void SendAccount(int input) {

	if (input >= '1' && input <= '9') input -= '1';
	else if (input == '0') input = 9;
	else if (input >= 'a' && input <= 'z') input = input - 'a' + 10;
	else if (input >= 'A' && input <= 'Z') input = input - 'A' + 36;
	else return;

	if (input != -1&&input<info_len) {

		Sleep(2000);
		//SetFocus(pid);
		keybd_event(VK_SHIFT, 0, 0, 0);
		keybd_event(VK_TAB, 0, 0, 0);
		Sleep(50);
		keybd_event(VK_TAB, 0, KEYEVENTF_KEYUP, 0);
		keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
		Sleep(50);
		keybd_event(VK_CONTROL, 0, 0, 0);
		keybd_event('A', 0, 0, 0);
		Sleep(50);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);
		Sleep(50);
		keybd_event(VK_BACK, 0, KEYEVENTF_KEYUP, 0);
		Sleep(50);
		keybd_event(VK_BACK, 0, KEYEVENTF_KEYUP, 0);
		Sleep(50);

		//SendInput()
		sendstr(infos[input].username);

		Sleep(50);
		keybd_event(VK_TAB, 0, 0, 0);
		Sleep(50);
		keybd_event(VK_TAB, 0, KEYEVENTF_KEYUP, 0);
		Sleep(50);

		sendstr(infos[input].password);

		Sleep(50);
		keybd_event(VK_RETURN, 0, 0, 0);
		Sleep(50);
		keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
		Sleep(50);
	}
}