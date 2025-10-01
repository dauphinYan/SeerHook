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

std::atomic<ClientType> g_clientType = ClientType::Unity;
std::atomic<bool> g_hookEnabled = true;
std::atomic<bool> g_running = true;
std::mutex g_dataMutex;
HMODULE hModule;

decltype(&recv) originalRecv = nullptr;
decltype(&send) originalSend = nullptr;
decltype(&recvfrom) originalRecvFrom = nullptr;

static const wchar_t *PIPE_NAME = L"\\\\.\\pipe\\SeerSocketHook";
static HANDLE hPipe = INVALID_HANDLE_VALUE;
static std::mutex pipeMutex;

// ---------------------- Logging System ----------------------
void WriteDebugLog(const std::string &level, const std::string &message, DWORD errorCode = 0)
{
    // Ensure log directory exists
    CreateDirectoryA("log", nullptr);

    std::ofstream logFile("log/sockethook_log.log", std::ios::app);
    if (logFile.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        DWORD threadId = GetCurrentThreadId();

        logFile << "["
                << std::setw(2) << std::setfill('0') << st.wHour << ":"
                << std::setw(2) << std::setfill('0') << st.wMinute << ":"
                << std::setw(2) << std::setfill('0') << st.wSecond << "."
                << std::setw(3) << std::setfill('0') << st.wMilliseconds
                << "][TID:" << threadId << "]"
                << "[" << level << "] "
                << message;

        if (errorCode != 0)
        {
            LPSTR errorBuffer = nullptr;
            FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, errorCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&errorBuffer, 0, nullptr);

            if (errorBuffer)
            {
                logFile << " | ErrorCode: " << errorCode << " (" << errorBuffer << ")";
                LocalFree(errorBuffer);
            }
            else
            {
                logFile << " | ErrorCode: " << errorCode;
            }
        }

        logFile << std::endl;
        logFile.close();
    }
}

#define LOG_INFO(msg) WriteDebugLog("INFO", msg)
#define LOG_WARN(msg) WriteDebugLog("WARN", msg)
#define LOG_ERROR(msg, code) WriteDebugLog("ERROR", msg, code)
#define LOG_DEBUG(msg) WriteDebugLog("DEBUG", msg)
// ------------------------------------------------------------

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

void InitPipeClient()
{
    LOG_INFO("Initializing pipe client...");

    int retryCount = 0;
    const int maxRetries = 10;

    while (retryCount < maxRetries)
    {
        hPipe = CreateFileW(
            PIPE_NAME,
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
        if (!WaitNamedPipeW(PIPE_NAME, 5000))
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

void InitHook(ClientType type)
{
    LOG_INFO("Initializing Hook, client type: " + std::to_string((int)type));

    g_clientType = type;

    if (MH_Initialize() != MH_OK)
    {
        LOG_ERROR("MH_Initialize failed.", GetLastError());
        return;
    }
    LOG_INFO("MH_Initialize succeeded.");

    // Wait for ws2_32.dll to load
    HMODULE ws2_32 = nullptr;
    int retryCount = 0;
    const int maxRetries = 50; // wait up to 5s

    while (retryCount < maxRetries && !ws2_32)
    {
        ws2_32 = GetModuleHandleW(L"ws2_32");
        if (!ws2_32)
        {
            LOG_DEBUG("ws2_32.dll not loaded yet, waiting... (Attempt " + std::to_string(retryCount + 1) + "/" + std::to_string(maxRetries) + ")");
            Sleep(100);
            retryCount++;
        }
    }

    if (!ws2_32)
    {
        LOG_ERROR("Failed to load ws2_32.dll, cannot continue.", GetLastError());
        return;
    }
    LOG_INFO("ws2_32.dll loaded successfully.");

    // Get target functions
    LPVOID targetRecv = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recv"));
    LPVOID targetSend = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "send"));
    LPVOID targetRecvFrom = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recvfrom"));

    if (!targetRecv || !targetSend)
    {
        LOG_ERROR("Failed to get recv/send function address.", GetLastError());
    }

    if (targetRecv)
    {
        if (MH_CreateHook(targetRecv, reinterpret_cast<LPVOID>(RecvEvent), reinterpret_cast<LPVOID *>(&originalRecv)) != MH_OK)
            LOG_ERROR("Failed to create recv hook.", GetLastError());
    }

    if (targetSend)
    {
        if (MH_CreateHook(targetSend, reinterpret_cast<LPVOID>(SendEvent), reinterpret_cast<LPVOID *>(&originalSend)) != MH_OK)
            LOG_ERROR("Failed to create send hook.", GetLastError());
    }

    if (targetRecvFrom)
    {
        if (MH_CreateHook(targetRecvFrom, reinterpret_cast<LPVOID>(RecvFromEvent), reinterpret_cast<LPVOID *>(&originalRecvFrom)) != MH_OK)
            LOG_ERROR("Failed to create recvfrom hook.", GetLastError());
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        LOG_ERROR("Failed to enable hooks.", GetLastError());
        return;
    }

    LOG_INFO("Hooks created and enabled successfully.");

    InitPipeClient();
    LOG_INFO("Hook initialization completed.");
}

DWORD WINAPI InitHook_Thread(LPVOID lpParam)
{
    LOG_INFO("InitHook_Thread started.");
    ClientType type = *reinterpret_cast<ClientType *>(lpParam);
    InitHook(type);
    LOG_INFO("InitHook_Thread finished.");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        LOG_INFO("DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hMod);
        hModule = hMod;
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        LOG_INFO("DLL_PROCESS_DETACH");
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
