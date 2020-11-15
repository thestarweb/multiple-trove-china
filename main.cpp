#include <stdio.h>
#include <stdlib.h>
#include "KillThread.h"
#include "HideHook.h"
#include "Start.h"
#include "account.h"

#include <conio.h>




int main() {
	printf("这是一个非常low的多开器 by 星星\n");
	printf("仅供技术交流请勿散播此文件\n");
	LoadAccount();
	DWORD pid;
	while (1)
	{
		ShowAccount();
		int input = getch();

		KillThread();
		if (pid = CreateIt()) {
			if (!SetHook(pid)) {
				printf("无法将钩子写入启动器\n");
			}
		}
		else
		{
			printf("无法打开启动器，请确保本程序工作在游戏启动器目录且系统有足够内存\n");
			system("pause");
			return 1;
		}
		RunIt();

		//

		//send_input

		SendAccount(input);

		printf("进入游戏后按任意键可继续打开启动器，需要关闭请直接点击右上角的红叉\n");
		//system("pause");
	}
	return 0;
}