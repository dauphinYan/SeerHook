#include "SocketHook.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <algorithm>

std::atomic<ClientType> g_clientType = ClientType::Unity;
std::atomic<bool> g_hookEnabled = true;
std::atomic<bool> g_running = true;
std::mutex g_dataMutex;
HMODULE hModule;

decltype(&recv) originalRecv = nullptr;
decltype(&send) originalSend = nullptr;
decltype(&recvfrom) originalRecvFrom = nullptr;
decltype(&sendto) originalSendTo = nullptr;

WSARecv_t originalWSARecv = nullptr;
WSARecvFrom_t originalWSARecvFrom = nullptr;

static const wchar_t *PIPE_NAME = L"\\\\.\\pipe\\SeerSocketHook";
static HANDLE hPipe = INVALID_HANDLE_VALUE;
static std::mutex pipeMutex;

void WriteDebugLog(const std::string &message)
{
    std::ofstream logFile("Log/Sockethook_debug.log", std::ios::app);
    if (logFile.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
                << message << std::endl;
        logFile.close();
    }
}

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

int WINAPI RecvFromEvent(SOCKET s, char *buf, int len, int flags, struct sockaddr* from, int* fromlen)
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

// -------------------- overlapped 管理 --------------------
// 我们为有 overlapped + completion routine 的情况建立一个 map：
// key = lpOverlapped, value = 原始 WSABUF 列表 + 原始 completion routine
struct OverlappedRecord
{
    std::vector<WSABUF> bufs;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE origRoutine;
};

static std::mutex g_overlappedMutex;
static std::unordered_map<LPWSAOVERLAPPED, OverlappedRecord> g_overlappedMap;

void RegisterOverlappedBuffers(LPWSAOVERLAPPED lpOverlapped, const std::vector<WSABUF>& bufs, LPWSAOVERLAPPED_COMPLETION_ROUTINE origRoutine)
{
    if (!lpOverlapped) return;
    std::lock_guard<std::mutex> lk(g_overlappedMutex);
    OverlappedRecord r;
    r.bufs = bufs;
    r.origRoutine = origRoutine;
    g_overlappedMap[lpOverlapped] = std::move(r);
}

void UnregisterOverlappedBuffers(LPWSAOVERLAPPED lpOverlapped)
{
    if (!lpOverlapped) return;
    std::lock_guard<std::mutex> lk(g_overlappedMutex);
    g_overlappedMap.erase(lpOverlapped);
}

// helper: 从 WSABUF 列表按 cbTransferred 拼接读取数据，然后发送
static void ReadAndSendFromWSABUFs(SOCKET s, const std::vector<WSABUF>& bufs, DWORD cbTransferred)
{
    if (cbTransferred == 0) return;
    // 临时缓冲区（堆分配以避免栈溢出）
    std::vector<char> tmp;
    tmp.reserve(cbTransferred);
    DWORD remaining = cbTransferred;
    for (const auto& w : bufs)
    {
        if (remaining == 0) break;
        DWORD take = (DWORD)std::min<size_t>(w.len, remaining);
        if (w.buf && take > 0)
        {
            tmp.insert(tmp.end(), w.buf, w.buf + take);
            remaining -= take;
        }
    }
    if (!tmp.empty())
    {
        std::lock_guard<std::mutex> lk(g_dataMutex);
        SendToInjector(s, tmp.data(), (size_t)tmp.size(), false);
    }
}

// 我们自己的 completion routine：在数据到达时被系统调用
static void CALLBACK MyWSACompletionRoutine(DWORD dwError, DWORD cbTransferred, LPWSAOVERLAPPED lpOverlapped, DWORD dwFlags)
{
    // 从 map 中查找 bufs并读取数据
    OverlappedRecord rec;
    {
        std::lock_guard<std::mutex> lk(g_overlappedMutex);
        auto it = g_overlappedMap.find(lpOverlapped);
        if (it != g_overlappedMap.end())
        {
            rec = it->second; // 复制一份出来使用
            // 注意：不要在这里删除 map 元素，让后面的 Unregister 调用清理，或者我们可以立即清理
            g_overlappedMap.erase(it);
        }
    }

    // 如果找到了 buffers，我们需要找到对应的 SOCKET — 遗憾的是，这里没有直接传回 SOCKET。
    // 但大部分应用会把 SOCKET 放在 OVERLAPPED 或旁边的结构里；如果没有，无法从 lpOverlapped 找到 socket。
    // 为了兼容较多情况，我们不能总是获得 SOCKET，因此我们尝试从 OVERLAPPED 的内存上下文无法可靠拿到 socket。
    // 为简单起见，我们假定用户在 Register 时能已经确保后续能识别 socket —— 但在本实现里我们无法保证获取 SOCKET。
    // 作为折衷：我们将尝试从 rec.buf 中读取数据并把 socket 设置为 0（接收端可视需要改进）
    // 这里最可行的办法是：在 RegisterOverlappedBuffers 时把 SOCKET 也一并注册 —— 下面的实现已修改为带 SOCKET 参数。

    //（本函数会被替换为接收 SOCKET 的版本，见下方实际 WSARecvEvent 的实现）
    // 占位：（实际代码不会执行到这里）
    (void)dwError; (void)cbTransferred; (void)lpOverlapped; (void)dwFlags;
}

// 为了能在 completion routine 中获得 SOCKET，我们将采用另一种方式：
// 当在 WSARecvEvent / WSARecvFromEvent 被调用时，我们把 SOCKET 与 lpOverlapped -> buffers 一同保存。
// 下面是真正的带 SOCKET 的 completion routine wrapper：
struct OverlappedRecordWithSocket
{
    SOCKET s;
    std::vector<WSABUF> bufs;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE origRoutine;
};

static std::unordered_map<LPWSAOVERLAPPED, OverlappedRecordWithSocket> g_overlappedMap2;

static void CALLBACK MyWSACompletionRoutine_WithSocket(DWORD dwError, DWORD cbTransferred, LPWSAOVERLAPPED lpOverlapped, DWORD dwFlags)
{
    OverlappedRecordWithSocket rec;
    {
        std::lock_guard<std::mutex> lk(g_overlappedMutex);
        auto it = g_overlappedMap2.find(lpOverlapped);
        if (it != g_overlappedMap2.end())
        {
            rec = it->second;
            g_overlappedMap2.erase(it);
        }
    }

    if (rec.s != INVALID_SOCKET && !rec.bufs.empty() && cbTransferred > 0)
    {
        // 将 WSABUF 列表里的数据拼接并发送（只读 cbTransferred 字节）
        std::vector<char> tmp;
        tmp.reserve(cbTransferred);
        DWORD remaining = cbTransferred;
        for (const auto& w : rec.bufs)
        {
            if (remaining == 0) break;
            DWORD take = (DWORD)std::min<size_t>(w.len, remaining);
            if (w.buf && take > 0)
            {
                tmp.insert(tmp.end(), w.buf, w.buf + take);
                remaining -= take;
            }
        }
        if (!tmp.empty())
        {
            std::lock_guard<std::mutex> lk(g_dataMutex);
            SendToInjector(rec.s, tmp.data(), tmp.size(), false);
        }
    }

    // 调用原始 completion routine（如果存在）
    if (rec.origRoutine)
    {
        rec.origRoutine(dwError, cbTransferred, lpOverlapped, dwFlags);
    }
}

// -------------------- WSARecv / WSARecvFrom 钩子实现 --------------------
// 注意：当 lpOverlapped == NULL 时，WSARecv 同步完成，我们可以直接读取返回字节数并把缓冲区发出。
// 当 lpOverlapped != NULL 且 lpCompletionRoutine 非空时，我们替换 completion routine 为 MyWSACompletionRoutine_WithSocket，并在 map 中注册 SOCKET + bufs + 原始 routine。
// 之后调用 originalWSARecv（替换后的 completion routine 会在完成时被调用）。

int WSARecvEvent(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!originalWSARecv)
    {
        // 如果未获取到原始指针，直接失败以防崩溃
        SetLastError(ERROR_PROC_NOT_FOUND);
        return SOCKET_ERROR;
    }

    // 如果是同步（lpOverlapped == NULL）
    if (lpOverlapped == NULL)
    {
        int ret = originalWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
        if (g_hookEnabled && ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0)
        {
            // 将多个 WSABUF 拼接成一个临时缓冲并发送
            DWORD toRead = *lpNumberOfBytesRecvd;
            std::vector<char> tmp;
            tmp.reserve(toRead);
            DWORD remaining = toRead;
            for (DWORD i = 0; i < dwBufferCount && remaining > 0; ++i)
            {
                DWORD take = (DWORD)std::min<size_t>(lpBuffers[i].len, remaining);
                if (take > 0 && lpBuffers[i].buf)
                {
                    tmp.insert(tmp.end(), lpBuffers[i].buf, lpBuffers[i].buf + take);
                    remaining -= take;
                }
            }
            if (!tmp.empty())
            {
                std::lock_guard<std::mutex> lk(g_dataMutex);
                SendToInjector(s, tmp.data(), tmp.size(), false);
            }
        }
        return ret;
    }
    else
    {
        // 异步：记录 buffers 与原始 completion routine，然后把 completion routine 替换为我们的 wrapper
        std::vector<WSABUF> bufs;
        bufs.reserve(dwBufferCount);
        for (DWORD i = 0; i < dwBufferCount; ++i)
        {
            bufs.push_back(lpBuffers[i]);
        }

        {
            std::lock_guard<std::mutex> lk(g_overlappedMutex);
            OverlappedRecordWithSocket rec;
            rec.s = s;
            rec.bufs = bufs;
            rec.origRoutine = lpCompletionRoutine;
            g_overlappedMap2[lpOverlapped] = std::move(rec);
        }

        // 调用原始 WSARecv，但把 completion routine 换成我们的 MyWSACompletionRoutine_WithSocket
        int ret = originalWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, MyWSACompletionRoutine_WithSocket);
        // 如果调用失败且不是 IO_PENDING，则清理 map
        if (ret == SOCKET_ERROR)
        {
            int err = WSAGetLastError();
            if (err != WSA_IO_PENDING)
            {
                std::lock_guard<std::mutex> lk(g_overlappedMutex);
                g_overlappedMap2.erase(lpOverlapped);
            }
        }
        return ret;
    }
}

int WSARecvFromEvent(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* from, LPINT fromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!originalWSARecvFrom)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return SOCKET_ERROR;
    }

    if (lpOverlapped == NULL)
    {
        int ret = originalWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, from, fromlen, lpOverlapped, lpCompletionRoutine);
        if (g_hookEnabled && ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0)
        {
            DWORD toRead = *lpNumberOfBytesRecvd;
            std::vector<char> tmp;
            tmp.reserve(toRead);
            DWORD remaining = toRead;
            for (DWORD i = 0; i < dwBufferCount && remaining > 0; ++i)
            {
                DWORD take = (DWORD)std::min<size_t>(lpBuffers[i].len, remaining);
                if (take > 0 && lpBuffers[i].buf)
                {
                    tmp.insert(tmp.end(), lpBuffers[i].buf, lpBuffers[i].buf + take);
                    remaining -= take;
                }
            }
            if (!tmp.empty())
            {
                std::lock_guard<std::mutex> lk(g_dataMutex);
                SendToInjector(s, tmp.data(), tmp.size(), false);
            }
        }
        return ret;
    }
    else
    {
        std::vector<WSABUF> bufs;
        bufs.reserve(dwBufferCount);
        for (DWORD i = 0; i < dwBufferCount; ++i)
        {
            bufs.push_back(lpBuffers[i]);
        }

        {
            std::lock_guard<std::mutex> lk(g_overlappedMutex);
            OverlappedRecordWithSocket rec;
            rec.s = s;
            rec.bufs = bufs;
            rec.origRoutine = lpCompletionRoutine;
            g_overlappedMap2[lpOverlapped] = std::move(rec);
        }

        int ret = originalWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, from, fromlen, lpOverlapped, MyWSACompletionRoutine_WithSocket);
        if (ret == SOCKET_ERROR)
        {
            int err = WSAGetLastError();
            if (err != WSA_IO_PENDING)
            {
                std::lock_guard<std::mutex> lk(g_overlappedMutex);
                g_overlappedMap2.erase(lpOverlapped);
            }
        }
        return ret;
    }
}

// -------------------- 管道与发送 --------------------
void InitPipeClient()
{
    WriteDebugLog("开始初始化管道客户端...");

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
            WriteDebugLog("管道连接成功!");
            break;
        }

        DWORD error = GetLastError();
        WriteDebugLog("管道连接失败，错误码: " + std::to_string(error));

        if (error != ERROR_PIPE_BUSY)
        {
            WriteDebugLog("管道不可用，等待重试...");
            Sleep(1000);
            retryCount++;
            continue;
        }

        WriteDebugLog("管道忙碌，等待可用...");
        if (!WaitNamedPipeW(PIPE_NAME, 5000))
        {
            WriteDebugLog("等待管道超时，重试...");
            retryCount++;
            continue;
        }
    }

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        WriteDebugLog("管道连接最终失败，达到最大重试次数");
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

    DWORD written = 0;
    WriteFile(hPipe, &header, sizeof(header), &written, nullptr);
    WriteFile(hPipe, data, header.payloadSize, &written, nullptr);
}

void InitHook(ClientType type)
{
    WriteDebugLog("开始初始化Hook，客户端类型: " + std::to_string((int)type));

    g_clientType = type;

    if (MH_Initialize() != MH_OK)
    {
        WriteDebugLog("MH_Initialize 失败");
        return;
    }
    WriteDebugLog("MH_Initialize 成功");

    // 等待 ws2_32.dll 加载
    HMODULE ws2_32 = nullptr;
    int retryCount = 0;
    const int maxRetries = 50; // 最多等待 5 秒

    while (retryCount < maxRetries && !ws2_32)
    {
        ws2_32 = GetModuleHandleW(L"ws2_32");
        if (!ws2_32)
        {
            WriteDebugLog("ws2_32.dll 尚未加载，等待中... (尝试 " + std::to_string(retryCount + 1) + "/" + std::to_string(maxRetries) + ")");
            Sleep(100);
            retryCount++;
        }
    }

    if (!ws2_32)
    {
        WriteDebugLog("ws2_32.dll 加载失败，无法继续");
        return;
    }
    WriteDebugLog("ws2_32.dll 加载成功");

    // 获取函数地址
    LPVOID targetRecv = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recv"));
    LPVOID targetSend = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "send"));
    LPVOID targetRecvFrom = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recvfrom"));
    LPVOID targetSendTo = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "sendto"));
    LPVOID targetWSARecv = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "WSARecv"));
    LPVOID targetWSARecvFrom = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "WSARecvFrom"));

    if (!targetRecv || !targetSend)
    {
        WriteDebugLog("获取 recv/send 函数地址失败");
        // 但我们继续尝试 WSARecv 等
    }

    // 创建 hook（ignore 部分失败的函数以便尽量多覆盖）
    if (targetRecv)
    {
        if (MH_CreateHook(targetRecv, reinterpret_cast<LPVOID>(RecvEvent), reinterpret_cast<LPVOID *>(&originalRecv)) != MH_OK)
            WriteDebugLog("创建 recv hook 失败");
    }

    if (targetSend)
    {
        if (MH_CreateHook(targetSend, reinterpret_cast<LPVOID>(SendEvent), reinterpret_cast<LPVOID *>(&originalSend)) != MH_OK)
            WriteDebugLog("创建 send hook 失败");
    }

    if (targetRecvFrom)
    {
        if (MH_CreateHook(targetRecvFrom, reinterpret_cast<LPVOID>(RecvFromEvent), reinterpret_cast<LPVOID *>(&originalRecvFrom)) != MH_OK)
            WriteDebugLog("创建 recvfrom hook 失败");
    }

    // if (targetSendTo)
    // {
    //     if (MH_CreateHook(targetSendTo, reinterpret_cast<LPVOID>(SendEvent), reinterpret_cast<LPVOID *>(&originalSendTo)) != MH_OK)
    //         WriteDebugLog("创建 sendto hook 失败");
    // }

    if (targetWSARecv)
    {
        if (MH_CreateHook(targetWSARecv, reinterpret_cast<LPVOID>(WSARecvEvent), reinterpret_cast<LPVOID *>(&originalWSARecv)) != MH_OK)
            WriteDebugLog("创建 WSARecv hook 失败");
    }

    // if (targetWSARecvFrom)
    // {
    //     if (MH_CreateHook(targetWSARecvFrom, reinterpret_cast<LPVOID>(WSARecvFromEvent), reinterpret_cast<LPVOID *>(&originalWSARecvFrom)) != MH_OK)
    //         WriteDebugLog("创建 WSARecvFrom hook 失败");
    // }

    // 启用所有已创建的 hook
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        WriteDebugLog("启用 Hook 失败");
        return;
    }

    WriteDebugLog("Hook 创建并启用完成");

    InitPipeClient();
    WriteDebugLog("Hook 初始化完成");
}

DWORD WINAPI InitHook_Thread(LPVOID lpParam)
{
    WriteDebugLog("InitHook_Thread 开始执行");
    ClientType type = *reinterpret_cast<ClientType *>(lpParam);
    InitHook(type);
    WriteDebugLog("InitHook_Thread 执行完成");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        WriteDebugLog("DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hMod);
        hModule = hMod;
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        WriteDebugLog("DLL_PROCESS_DETACH");
        HMODULE ws2_32 = GetModuleHandleW(L"ws2_32");
        if (ws2_32)
        {
            // 禁用所有我们可能创建的 hook（如果不存在会被忽略）
            LPVOID p;
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recv"));
            if (p) MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "send"));
            if (p) MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "recvfrom"));
            if (p) MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "sendto"));
            if (p) MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "WSARecv"));
            if (p) MH_DisableHook(p);
            p = reinterpret_cast<LPVOID>(GetProcAddress(ws2_32, "WSARecvFrom"));
            if (p) MH_DisableHook(p);
        }
        MH_Uninitialize();
    }
    return TRUE;
}
