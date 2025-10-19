#pragma once

#include <winsock2.h>
#include <windows.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>

#include "MinHook.h"

enum class ClientType
{
    Flash,
    Unity
};

struct RemoteArguement
{
    ClientType clientType;
    wchar_t pid[32];
};

struct PacketHeader
{
    uint32_t totalSize;
    uint32_t socket;
    uint32_t payloadSize;
    uint8_t direction; // 0 = recv, 1 = send
};

extern std::atomic<ClientType> g_clientType;
extern std::atomic<bool> g_hookEnabled;
extern std::mutex g_dataMutex;

extern decltype(&recv) originalRecv;
extern decltype(&send) originalSend;
extern decltype(&recvfrom) originalRecvFrom;

// 导出的事件回调（钩子函数）
extern int WINAPI RecvEvent(SOCKET, char *, int, int);
extern int WINAPI RecvFromEvent(SOCKET, char *, int, int, struct sockaddr *, int *);
extern int WINAPI SendEvent(SOCKET, char *, int, int);

// 管道和发送数据到注入端的函数
extern void InitPipeClient(std::wstring pid);
extern void SendToInjector(SOCKET s, const char *data, size_t len, bool isSend);

// 供外部调用的函数
extern "C" __declspec(dllexport)
DWORD WINAPI
InitHook(LPVOID lpParam);
