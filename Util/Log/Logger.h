#pragma once

#include <windows.h>
#include <string>
#include <format>

namespace Logger
{
    void WriteDebugLog(const std::string& level, const std::string& message, DWORD errorCode = 0);
}

#define LOG_INFO(msg)  Logger::WriteDebugLog("INFO", msg)

#define LOG_WARN(msg)  Logger::WriteDebugLog("WARN", msg)

#define LOG_ERROR(msg, code) Logger::WriteDebugLog("ERROR", msg, code)

#define LOG_DEBUG(msg) Logger::WriteDebugLog("DEBUG", msg)