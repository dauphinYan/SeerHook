#include "Logger.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace Logger
{
    void WriteDebugLog(const std::string& level, const std::string& message, DWORD errorCode)
    {
        CreateDirectoryA("log", nullptr);

        std::ofstream logFile("log/sockethook_log.log", std::ios::app);
        if (!logFile.is_open())
            return;

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
            // DWORD formatResult = FormatMessageA(
            //     FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            //     nullptr,
            //     errorCode,
            //     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            //     (LPSTR)&errorBuffer,
            //     0,
            //     nullptr);

            if (errorBuffer)
            {
                char* end = errorBuffer + strlen(errorBuffer) - 1;
                while (end >= errorBuffer && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
                {
                    *end = '\0';
                    --end;
                }

                logFile << " | ErrorCode: " << errorCode << " (" << errorBuffer << ")";
                LocalFree(errorBuffer);
            }
            else
            {
                logFile << " | ErrorCode: " << errorCode << " (No description available, FormatMessage failed: "
                        << GetLastError() << ")";
            }
        }

        logFile << std::endl;
    }
}