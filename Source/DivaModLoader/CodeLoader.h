﻿#pragma once

typedef void CodeEvent();

struct CodeEventPair
{
    std::wstring directoryPath;
    CodeEvent* event;

    void run() const;
};

class CodeLoader
{
public:
    static std::vector<std::wstring> dllFilePaths;

    static std::vector<CodeEventPair> initEvents;
    static std::vector<CodeEventPair> postInitEvents;
    static std::vector<CodeEvent*> onFrameEvents;

    static void init();
    static void postInit();
};