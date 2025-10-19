#include "SocketHook.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <tchar.h>
#include <strsafe.h>

#include "Util/Log/Logger.h"

std::atomic<ClientType> g_clientType = ClientType::Unity;
std::atomic<bool> g_hookEnabled = true;
std::mutex g_dataMutex;

decltype(&recv) originalRecv = nullptr;
decltype(&send) originalSend = nullptr;
decltype(&recvfrom) originalRecvFrom = nullptr;

static std::wstring PIPE_NAME = L"\\\\.\\pipe\\SeerSocketHook_";
static HANDLE hPipe = INVALID_HANDLE_VALUE;
static std::mutex pipeMutex;

int WINAPI RecvEvent(SOCKET s, char *buf, int len, int flags)
{
    int ret = originalRecv(s, buf, len, flags);
    if (g_hookEnabled && ret > 0)
    {
        std::lock_guard<std::mutex> lk(g_dataMutex);
        SendToInjector(s, buf, ret, false);
    }
    return ret;
}

int WINAPI RecvFromEvent(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
    int ret = originalRecvFrom(s, buf, len, flags, from, fromlen);
    if (g_hookEnabled && ret > 0)
    {
        std::lock_guard<std::mutex> lk(g_dataMutex);
        SendToInjector(s, buf, ret, false);
    }
    return ret;
}

int WINAPI SendEvent(SOCKET s, char *buf, int len, int flags)
{
    int ret = originalSend(s, buf, len, flags);
    if (g_hookEnabled && ret > 0)
    {
        std::lock_guard<std::mutex> lk(g_dataMutex);
        SendToInjector(s, buf, ret, true);
    }
    return ret;
}

void InitPipeClient(std::wstring pid)
{
    LOG_INFO("Initializing pipe client...");

    std::wstring pipeName = PIPE_NAME + pid;
    std::string str(pipeName.begin(), pipeName.end());
    LOG_INFO("Successfully connected to named pipe: " + str);

    int retryCount = 0;
    const int maxRetries = 10;

    while (retryCount < maxRetries)
    {
        hPipe = CreateFileW(
            pipeName.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            nullptr);

        if (hPipe != INVALID_HANDLE_VALUE)
        {
            LOG_INFO("Successfully connected to named pipe.");
            break;
        }

        DWORD error = GetLastError();
        LOG_WARN("Failed to connect to pipe.");
        if (error != ERROR_PIPE_BUSY)
        {
            LOG_WARN("Pipe not available, retrying...");
            Sleep(1000);
            retryCount++;
            continue;
        }

        LOG_INFO("Pipe is busy, waiting...");
        if (!WaitNamedPipeW(pipeName.c_str(), 5000))
        {
            LOG_WARN("WaitNamedPipe timed out, retrying...");
            retryCount++;
            continue;
        }
    }

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("Failed to connect to named pipe after maximum retries.", GetLastError());
    }
}

void SendToInjector(SOCKET s, const char *data, size_t len, bool isSend)
{
    std::lock_guard<std::mutex> lk(pipeMutex);
    if (hPipe == INVALID_HANDLE_VALUE)
        return;

    PacketHeader header;
    header.socket = (uint32_t)(uintptr_t)s;
    header.payloadSize = (uint32_t)len;
    header.direction = isSend ? 1 : 0;
    header.totalSize = sizeof(PacketHeader) + header.payloadSize;

    std::vector<char> buffer(sizeof(PacketHeader) + len);
    memcpy(buffer.data(), &header, sizeof(PacketHeader));
    memcpy(buffer.data() + sizeof(PacketHeader), data, len);

    DWORD written = 0;
    BOOL result = WriteFile(hPipe, buffer.data(), (DWORD)buffer.size(), &written, nullptr);
    if (!result)
    {
        DWORD error = GetLastError();
        LOG_ERROR("Failed to write data to pipe.", error);
        return;
    }
}

DWORD WINAPI InitHook(LPVOID lpParam)
{
    LOG_INFO("Start to cast lpParam.");
    RemoteArguement *arg = reinterpret_cast<RemoteArguement *>(lpParam);
    ClientType type = arg->clientType;
    std::wstring pid(arg->pid);
    LOG_INFO("Cast lpParam success.");

    if (MH_Initialize() != MH_OK)
    {
        LOG_ERROR("MH_Initialize failed.", 0);
        return 1;
    }
    LOG_INFO("MH_Initialize succeeded.");

    HMODULE ws2_32 = nullptr;
    const int maxRetries = 50;
    for (int retryCount = 0; retryCount < maxRetries && !ws2_32; ++retryCount)
    {
        ws2_32 = GetModuleHandleW(L"ws2_32");
        if (!ws2_32)
        {
            LOG_DEBUG("ws2_32.dll not loaded yet, waiting... (Attempt " +
                      std::to_string(retryCount + 1) + "/" +
                      std::to_string(maxRetries) + ")");
            Sleep(100);
        }
    }

    if (!ws2_32)
    {
        LOG_ERROR("Failed to load ws2_32.dll, cannot continue.", 0);
        MH_Uninitialize();
        return 1;
    }
    LOG_INFO("ws2_32.dll loaded successfully.");

    LPVOID targetRecv = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recv"));
    LPVOID targetSend = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "send"));
    LPVOID targetRecvFrom = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recvfrom"));

    if (!targetRecv || !targetSend)
    {
        LOG_ERROR("Failed to get recv/send function address.", 0);
        MH_Uninitialize();
        return 1;
    }

    if (targetRecv)
    {
        if (MH_CreateHook(targetRecv, reinterpret_cast<LPVOID>(RecvEvent), reinterpret_cast<LPVOID *>(&originalRecv)) != MH_OK)
            LOG_ERROR("Failed to create recv hook.", 0);
    }

    if (targetSend)
    {
        if (MH_CreateHook(targetSend, reinterpret_cast<LPVOID>(SendEvent), reinterpret_cast<LPVOID *>(&originalSend)) != MH_OK)
            LOG_ERROR("Failed to create send hook.", 0);
    }

    if (targetRecvFrom)
    {
        if (MH_CreateHook(targetRecvFrom, reinterpret_cast<LPVOID>(RecvFromEvent), reinterpret_cast<LPVOID *>(&originalRecvFrom)) != MH_OK)
            LOG_ERROR("Failed to create recvfrom hook.", 0);
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        LOG_ERROR("Failed to enable hooks.", 0);
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        return 1;
    }

    LOG_INFO("Hooks created and enabled successfully.");

    InitPipeClient(pid);

    LOG_INFO("Hook initialization completed.");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        LOG_INFO("DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hMod);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        LOG_INFO("DLL_PROCESS_DETACH");

        if (hPipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }

        HMODULE ws2_32 = GetModuleHandleW(L"ws2_32");
        if (ws2_32)
        {
            LPVOID p;
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recv"));
            if (p)
                MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "send"));
            if (p)
                MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recvfrom"));
            if (p)
                MH_DisableHook(p);
        }
        MH_Uninitialize();
    }
    return TRUE;
}
