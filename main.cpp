#include <stdio.h>
#include <stdlib.h>
#include "KillThread.h"
#include "HideHook.h"
#include "Start.h"
#include "account.h"

#include <conio.h>




int main() {
	printf("����һ���ǳ�low�Ķ࿪�� by ����\n");
	printf("����������������ɢ�����ļ�\n");
	LoadAccount();
	DWORD pid;
	while (1)
	{
		ShowAccount();
		int input = getch();

		KillThread();
		if (pid = CreateIt()) {
			if (!SetHook(pid)) {
				printf("�޷�������д��������\n");
			}
		}
		else
		{
			printf("�޷�������������ȷ��������������Ϸ������Ŀ¼��ϵͳ���㹻�ڴ�\n");
			system("pause");
			return 1;
		}
		RunIt();

		//

		//send_input

		SendAccount(input);

		printf("������Ϸ��������ɼ���������������Ҫ�ر���ֱ�ӵ�����Ͻǵĺ��\n");
		//system("pause");
	}
	return 0;
}