#pragma once

#include <winsock2.h>
#include <windows.h>
#include <atomic>
#include <mutex>

#include "MinHook.h"
#include <vector>

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

// 原始函数指针（我们会保存它们以便在钩子中调用真实实现）
extern decltype(&recv) originalRecv;
extern decltype(&send) originalSend;
extern decltype(&recvfrom) originalRecvFrom;
extern decltype(&sendto) originalSendTo;

// WSARecv / WSARecvFrom 的函数类型与原始指针
typedef int (WSAAPI *WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

extern WSARecv_t originalWSARecv;
extern WSARecvFrom_t originalWSARecvFrom;

// 导出的事件回调（钩子函数）
extern int WINAPI RecvEvent(SOCKET, char *, int, int);
extern int WINAPI RecvFromEvent(SOCKET, char *, int, int, struct sockaddr*, int*);
extern int WSARecvEvent(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
extern int WSARecvFromEvent(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
extern int WINAPI SendEvent(SOCKET, char *, int, int);

// 管道和发送数据到注入端的函数
extern void InitPipeClient();
extern void SendToInjector(SOCKET s, const char *data, size_t len, bool isSend);
extern void InitHook(ClientType type);

// 需要外部调用的函数。
extern "C" __declspec(dllexport)
DWORD WINAPI
InitHook_Thread(LPVOID lpParam);

// 供 completion routine 路径使用（内部实现用）
extern void RegisterOverlappedBuffers(LPWSAOVERLAPPED lpOverlapped, const std::vector<WSABUF>& bufs, LPWSAOVERLAPPED_COMPLETION_ROUTINE origRoutine);
extern void UnregisterOverlappedBuffers(LPWSAOVERLAPPED lpOverlapped);
