#pragma once

#include <winsock2.h>
#include <windows.h>
#include <atomic>
#include <mutex>

#include "MinHook.h"

enum class ClientType
{
    Flash,
    Unity
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
extern std::atomic<bool> g_running;
extern std::mutex g_dataMutex;

extern decltype(&recv) originalRecv;
extern decltype(&send) originalSend;

extern int WINAPI RecvEvent(SOCKET, char *, int, int);
extern int WINAPI SendEvent(SOCKET, char *, int, int);

extern void InitPipeClient();
extern void SendToInjector(SOCKET s, const char *data, size_t len, bool isSend);
extern void InitHook(ClientType type);

// 需要外部调用的函数。
extern "C" __declspec(dllexport)
DWORD WINAPI
InitHook_Thread(LPVOID lpParam);