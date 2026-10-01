#include "mex.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
constexpr std::uintptr_t kDecoderRva = 0x7E990;
constexpr std::uintptr_t kFirstAggregatorRva = 0xAC0C0; // record type 19
constexpr std::uintptr_t kPermutationCallbackRva = 0xBBC50;
constexpr std::size_t kOverwriteSize = 15;
constexpr std::array<std::uint8_t, kOverwriteSize> kExpectedPrologue = {
    0x48, 0x89, 0x5C, 0x24, 0x08,
    0x48, 0x89, 0x6C, 0x24, 0x18,
    0x48, 0x89, 0x74, 0x24, 0x20,
};
constexpr std::array<std::uint8_t, kOverwriteSize> kExpectedPermutationPrologue = {
    0x48, 0x89, 0x5C, 0x24, 0x08,
    0x48, 0x89, 0x6C, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18,
};

struct Record {
    std::uint8_t type;
    std::uint8_t mask;
    bool hasPayload;
    std::uint32_t value;
    std::vector<std::uint8_t> payload;
};

struct PermutationEvent {
    std::uint64_t recordIndex;
    std::uint32_t mode;
    std::uint32_t count;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> placements;
};

struct IteratorInfo {
    void* callback;
    std::size_t eventIndex;
};

using Decoder = std::uint8_t* (*)(std::uint8_t*, void*, std::uint8_t);
using Aggregator = std::uint64_t (*)(std::uint32_t, void*, std::intptr_t*, std::uintptr_t);
using PermutationFactory = void* (*)(void*, std::uint32_t, std::uint32_t);
using PermutationCallback = std::uint32_t (*)(void*, std::uint32_t, std::uint32_t,
                                              std::uintptr_t, std::uintptr_t, std::uintptr_t);

std::mutex gMutex;
std::vector<Record> gRecords;
std::vector<PermutationEvent> gPermutationEvents;
std::unordered_map<void*, IteratorInfo> gIteratorInfo;
std::vector<void**> gProxyVtables;
Decoder gOriginal = nullptr;
std::uint8_t* gTarget = nullptr;
void* gTrampoline = nullptr;
Aggregator gOriginalAggregator = nullptr;
std::uint8_t* gAggregatorTarget = nullptr;
void* gAggregatorTrampoline = nullptr;
PermutationCallback gOriginalPermutation = nullptr;
std::uint8_t* gPermutationTarget = nullptr;
void* gPermutationTrampoline = nullptr;
PermutationFactory gOriginalFactory = nullptr;
void** gFactorySlot = nullptr;
thread_local std::uint64_t gLastRecordIndex = UINT64_MAX;
std::uintptr_t gModuleBase = 0;
std::uintptr_t gObservedCallbackRva = 0;
bool gInstalled = false;
bool gCaptureFailed = false;

void writeAbsoluteJump(std::uint8_t* destination, const void* target) {
    destination[0] = 0x48;
    destination[1] = 0xB8; // mov rax, imm64
    const auto address = reinterpret_cast<std::uintptr_t>(target);
    std::memcpy(destination + 2, &address, sizeof(address));
    destination[10] = 0xFF;
    destination[11] = 0xE0; // jmp rax
}

void writeExecutableBytes(std::uint8_t* destination, const std::uint8_t* source,
                          std::size_t size) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(destination, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        mexErrMsgIdAndTxt("pcode:trace:VirtualProtect", "VirtualProtect failed (%lu).",
                          GetLastError());
    }
    std::memcpy(destination, source, size);
    FlushInstructionCache(GetCurrentProcess(), destination, size);
    DWORD ignored = 0;
    if (!VirtualProtect(destination, size, oldProtect, &ignored)) {
        mexErrMsgIdAndTxt("pcode:trace:RestoreProtection",
                          "Could not restore memory protection (%lu).", GetLastError());
    }
}

std::uint8_t* traceDecoder(std::uint8_t* output, void* stream, std::uint8_t mask) noexcept {
    std::uint8_t* result = gOriginal(output, stream, mask);
    try {
        Record record{};
        record.type = output[0];
        record.mask = mask;
        std::uint32_t length = 0;
        std::memcpy(&length, output + 4, sizeof(length));
        record.value = length;
        void* payload = nullptr;
        std::memcpy(&payload, output + 8, sizeof(payload));
        record.hasPayload = length != 0 && payload != nullptr;
        if (record.hasPayload) {
            const auto* first = static_cast<const std::uint8_t*>(payload);
            record.payload.assign(first, first + length);
        }
        std::lock_guard<std::mutex> lock(gMutex);
        gRecords.emplace_back(std::move(record));
        gLastRecordIndex = static_cast<std::uint64_t>(gRecords.size() - 1);
    } catch (...) {
        gCaptureFailed = true;
    }
    return result;
}

std::uint32_t tracePermutation(void* iterator, std::uint32_t sourceIndex,
                               std::uint32_t count, std::uintptr_t opaque,
                               std::uintptr_t item, std::uintptr_t itemTag) noexcept {
    try {
        IteratorInfo info{};
        {
            std::lock_guard<std::mutex> lock(gMutex);
            const auto found = gIteratorInfo.find(iterator);
            if (found == gIteratorInfo.end()) {
                return gOriginalPermutation(iterator, sourceIndex, count, opaque, item, itemTag);
            }
            info = found->second;
        }
        auto callback = reinterpret_cast<PermutationCallback>(info.callback);
        const std::uint32_t destination = callback(iterator, sourceIndex, count, opaque,
                                                   item, itemTag);
        {
            std::lock_guard<std::mutex> lock(gMutex);
            if (info.eventIndex < gPermutationEvents.size()) {
                gPermutationEvents[info.eventIndex].placements.emplace_back(sourceIndex,
                                                                             destination);
            }
        }
        return destination;
    } catch (...) {
        gCaptureFailed = true;
        return sourceIndex;
    }
}

void* tracePermutationFactory(void* factory, std::uint32_t mode,
                              std::uint32_t count) noexcept {
    void* iterator = gOriginalFactory(factory, mode, count);
    try {
        if (iterator == nullptr) {
            return iterator;
        }
        auto*** object = reinterpret_cast<void***>(iterator);
        void** originalVtable = *object;
        std::lock_guard<std::mutex> lock(gMutex);
        gObservedCallbackRva = reinterpret_cast<std::uintptr_t>(originalVtable[1]) - gModuleBase;
        const std::size_t eventIndex = gPermutationEvents.size();
        gPermutationEvents.push_back(
            {gLastRecordIndex, mode, count, {}});
        gIteratorInfo[iterator] = {reinterpret_cast<void*>(gOriginalPermutation), eventIndex};
    } catch (...) {
        gCaptureFailed = true;
    }
    return iterator;
}

void installFactoryHook(std::intptr_t* context) {
    if (gFactorySlot != nullptr || context == nullptr || context[0x17] == 0) {
        return;
    }
    auto*** factoryObject = reinterpret_cast<void***>(context[0x17]);
    void** vtable = *factoryObject;
    void** slot = vtable + 1;
    gOriginalFactory = reinterpret_cast<PermutationFactory>(*slot);

    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        mexErrMsgIdAndTxt("pcode:trace:FactoryProtect",
                          "Could not patch permutation factory vtable (%lu).", GetLastError());
    }
    *slot = reinterpret_cast<void*>(&tracePermutationFactory);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
    DWORD ignored = 0;
    if (!VirtualProtect(slot, sizeof(void*), oldProtect, &ignored)) {
        mexErrMsgIdAndTxt("pcode:trace:FactoryRestoreProtection",
                          "Could not restore permutation vtable protection (%lu).",
                          GetLastError());
    }
    gFactorySlot = slot;
}

std::uint64_t traceFirstAggregator(std::uint32_t count, void* payload,
                                   std::intptr_t* context, std::uintptr_t opaque) {
    installFactoryHook(context);
    return gOriginalAggregator(count, payload, context, opaque);
}

void clearCapturedData() {
    std::lock_guard<std::mutex> lock(gMutex);
    gRecords.clear();
    gPermutationEvents.clear();
    gIteratorInfo.clear();
    for (void** proxy : gProxyVtables) {
        delete[] proxy;
    }
    gProxyVtables.clear();
    gLastRecordIndex = UINT64_MAX;
    gCaptureFailed = false;
}

void uninstall() noexcept {
    if (!gInstalled) {
        return;
    }
    if (gFactorySlot != nullptr && gOriginalFactory != nullptr) {
        DWORD oldProtect = 0;
        if (VirtualProtect(gFactorySlot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
            *gFactorySlot = reinterpret_cast<void*>(gOriginalFactory);
            FlushInstructionCache(GetCurrentProcess(), gFactorySlot, sizeof(void*));
            DWORD ignored = 0;
            VirtualProtect(gFactorySlot, sizeof(void*), oldProtect, &ignored);
        }
    }
    DWORD oldProtect = 0;
    if (VirtualProtect(gTarget, kOverwriteSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::memcpy(gTarget, kExpectedPrologue.data(), kOverwriteSize);
        FlushInstructionCache(GetCurrentProcess(), gTarget, kOverwriteSize);
        DWORD ignored = 0;
        VirtualProtect(gTarget, kOverwriteSize, oldProtect, &ignored);
    }
    if (gAggregatorTarget != nullptr &&
        VirtualProtect(gAggregatorTarget, kOverwriteSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::memcpy(gAggregatorTarget, kExpectedPrologue.data(), kOverwriteSize);
        FlushInstructionCache(GetCurrentProcess(), gAggregatorTarget, kOverwriteSize);
        DWORD ignored = 0;
        VirtualProtect(gAggregatorTarget, kOverwriteSize, oldProtect, &ignored);
    }
    if (gPermutationTarget != nullptr &&
        VirtualProtect(gPermutationTarget, kOverwriteSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::memcpy(gPermutationTarget, kExpectedPermutationPrologue.data(), kOverwriteSize);
        FlushInstructionCache(GetCurrentProcess(), gPermutationTarget, kOverwriteSize);
        DWORD ignored = 0;
        VirtualProtect(gPermutationTarget, kOverwriteSize, oldProtect, &ignored);
    }
    if (gTrampoline != nullptr) {
        VirtualFree(gTrampoline, 0, MEM_RELEASE);
    }
    if (gAggregatorTrampoline != nullptr) {
        VirtualFree(gAggregatorTrampoline, 0, MEM_RELEASE);
    }
    if (gPermutationTrampoline != nullptr) {
        VirtualFree(gPermutationTrampoline, 0, MEM_RELEASE);
    }
    for (void** proxy : gProxyVtables) {
        delete[] proxy;
    }
    gProxyVtables.clear();
    gIteratorInfo.clear();
    gTrampoline = nullptr;
    gOriginal = nullptr;
    gTarget = nullptr;
    gAggregatorTrampoline = nullptr;
    gOriginalAggregator = nullptr;
    gAggregatorTarget = nullptr;
    gPermutationTrampoline = nullptr;
    gOriginalPermutation = nullptr;
    gPermutationTarget = nullptr;
    gOriginalFactory = nullptr;
    gFactorySlot = nullptr;
    gInstalled = false;
}

void atExit() {
    uninstall();
}

void install() {
    if (gInstalled) {
        return;
    }
    HMODULE module = GetModuleHandleW(L"fe_osp.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"fe_osp.dll");
    }
    gModuleBase = reinterpret_cast<std::uintptr_t>(module);
    if (module == nullptr) {
        mexErrMsgIdAndTxt("pcode:trace:LoadLibrary", "Could not load fe_osp.dll (%lu).",
                          GetLastError());
    }
    gTarget = reinterpret_cast<std::uint8_t*>(module) + kDecoderRva;
    gAggregatorTarget = reinterpret_cast<std::uint8_t*>(module) + kFirstAggregatorRva;
    gPermutationTarget = reinterpret_cast<std::uint8_t*>(module) + kPermutationCallbackRva;
    if (std::memcmp(gTarget, kExpectedPrologue.data(), kOverwriteSize) != 0) {
        mexErrMsgIdAndTxt("pcode:trace:UnexpectedBytes",
                          "Unexpected decoder prologue; this helper only supports the analyzed R2025a build.");
    }
    if (std::memcmp(gAggregatorTarget, kExpectedPrologue.data(), kOverwriteSize) != 0) {
        mexErrMsgIdAndTxt("pcode:trace:UnexpectedAggregatorBytes",
                          "Unexpected aggregator prologue; this helper only supports the analyzed R2025a build.");
    }
    if (std::memcmp(gPermutationTarget, kExpectedPermutationPrologue.data(),
                    kOverwriteSize) != 0) {
        mexErrMsgIdAndTxt("pcode:trace:UnexpectedPermutationBytes",
                          "Unexpected permutation callback prologue; this helper only supports the analyzed R2025a build.");
    }

    constexpr std::size_t kTrampolineSize = kOverwriteSize + 12;
    gTrampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (gTrampoline == nullptr) {
        mexErrMsgIdAndTxt("pcode:trace:VirtualAlloc", "VirtualAlloc failed (%lu).",
                          GetLastError());
    }
    auto* trampolineBytes = static_cast<std::uint8_t*>(gTrampoline);
    std::memcpy(trampolineBytes, kExpectedPrologue.data(), kOverwriteSize);
    writeAbsoluteJump(trampolineBytes + kOverwriteSize, gTarget + kOverwriteSize);
    FlushInstructionCache(GetCurrentProcess(), gTrampoline, kTrampolineSize);
    gOriginal = reinterpret_cast<Decoder>(gTrampoline);

    gAggregatorTrampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (gAggregatorTrampoline == nullptr) {
        mexErrMsgIdAndTxt("pcode:trace:AggregatorVirtualAlloc",
                          "VirtualAlloc failed for aggregator trampoline (%lu).", GetLastError());
    }
    auto* aggregatorTrampolineBytes = static_cast<std::uint8_t*>(gAggregatorTrampoline);
    std::memcpy(aggregatorTrampolineBytes, kExpectedPrologue.data(), kOverwriteSize);
    writeAbsoluteJump(aggregatorTrampolineBytes + kOverwriteSize,
                      gAggregatorTarget + kOverwriteSize);
    FlushInstructionCache(GetCurrentProcess(), gAggregatorTrampoline, kTrampolineSize);
    gOriginalAggregator = reinterpret_cast<Aggregator>(gAggregatorTrampoline);

    gPermutationTrampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (gPermutationTrampoline == nullptr) {
        mexErrMsgIdAndTxt("pcode:trace:PermutationVirtualAlloc",
                          "VirtualAlloc failed for permutation trampoline (%lu).", GetLastError());
    }
    auto* permutationTrampolineBytes = static_cast<std::uint8_t*>(gPermutationTrampoline);
    std::memcpy(permutationTrampolineBytes, kExpectedPermutationPrologue.data(), kOverwriteSize);
    writeAbsoluteJump(permutationTrampolineBytes + kOverwriteSize,
                      gPermutationTarget + kOverwriteSize);
    FlushInstructionCache(GetCurrentProcess(), gPermutationTrampoline, kTrampolineSize);
    gOriginalPermutation = reinterpret_cast<PermutationCallback>(gPermutationTrampoline);

    std::array<std::uint8_t, kOverwriteSize> patch{};
    writeAbsoluteJump(patch.data(), reinterpret_cast<const void*>(&traceDecoder));
    std::fill(patch.begin() + 12, patch.end(), 0x90);
    writeExecutableBytes(gTarget, patch.data(), patch.size());
    writeAbsoluteJump(patch.data(), reinterpret_cast<const void*>(&traceFirstAggregator));
    std::fill(patch.begin() + 12, patch.end(), 0x90);
    writeExecutableBytes(gAggregatorTarget, patch.data(), patch.size());
    writeAbsoluteJump(patch.data(), reinterpret_cast<const void*>(&tracePermutation));
    std::fill(patch.begin() + 12, patch.end(), 0x90);
    writeExecutableBytes(gPermutationTarget, patch.data(), patch.size());
    gInstalled = true;
    mexLock();
}

std::string getCommand(const mxArray* value) {
    if (!mxIsChar(value)) {
        mexErrMsgIdAndTxt("pcode:trace:BadCommand", "The first input must be a character vector.");
    }
    char* text = mxArrayToUTF8String(value);
    if (text == nullptr) {
        mexErrMsgIdAndTxt("pcode:trace:BadCommand", "Could not decode command.");
    }
    std::string result(text);
    mxFree(text);
    return result;
}

void saveRecords(const mxArray* pathValue) {
    char* path = mxArrayToUTF8String(pathValue);
    if (path == nullptr) {
        mexErrMsgIdAndTxt("pcode:trace:BadPath", "Could not decode output path.");
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    mxFree(path);
    if (!output) {
        mexErrMsgIdAndTxt("pcode:trace:OpenOutput", "Could not open trace output file.");
    }

    std::lock_guard<std::mutex> lock(gMutex);
    const std::array<char, 8> magic = {'P', 'C', 'T', 'R', '0', '0', '0', '3'};
    output.write(magic.data(), magic.size());
    const std::uint64_t count = static_cast<std::uint64_t>(gRecords.size());
    output.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const Record& record : gRecords) {
        const std::uint16_t flags = record.hasPayload ? 1 : 0;
        const std::uint32_t payloadLength = static_cast<std::uint32_t>(record.payload.size());
        output.put(static_cast<char>(record.type));
        output.put(static_cast<char>(record.mask));
        output.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
        output.write(reinterpret_cast<const char*>(&record.value), sizeof(record.value));
        output.write(reinterpret_cast<const char*>(&payloadLength), sizeof(payloadLength));
        if (payloadLength != 0) {
            output.write(reinterpret_cast<const char*>(record.payload.data()), payloadLength);
        }
    }
    const std::uint64_t permutationCount =
        static_cast<std::uint64_t>(gPermutationEvents.size());
    output.write(reinterpret_cast<const char*>(&permutationCount), sizeof(permutationCount));
    for (const PermutationEvent& event : gPermutationEvents) {
        output.write(reinterpret_cast<const char*>(&event.recordIndex), sizeof(event.recordIndex));
        output.write(reinterpret_cast<const char*>(&event.mode), sizeof(event.mode));
        output.write(reinterpret_cast<const char*>(&event.count), sizeof(event.count));
        const std::uint32_t placementCount =
            static_cast<std::uint32_t>(event.placements.size());
        output.write(reinterpret_cast<const char*>(&placementCount), sizeof(placementCount));
        for (const auto& placement : event.placements) {
            output.write(reinterpret_cast<const char*>(&placement.first), sizeof(placement.first));
            output.write(reinterpret_cast<const char*>(&placement.second), sizeof(placement.second));
        }
    }
    if (!output) {
        mexErrMsgIdAndTxt("pcode:trace:WriteOutput", "Failed while writing trace output.");
    }
}
} // namespace

void mexFunction(int nlhs, mxArray* plhs[], int nrhs, const mxArray* prhs[]) {
    if (nrhs < 1) {
        mexErrMsgIdAndTxt("pcode:trace:Usage",
                          "Usage: pcode_record_trace('start'|'clear'|'save'|'stop'|'status', ...)");
    }
    const std::string command = getCommand(prhs[0]);
    if (command == "start") {
        if (nrhs != 1 || nlhs > 0) {
            mexErrMsgIdAndTxt("pcode:trace:Usage", "Usage: pcode_record_trace('start')");
        }
        install();
        mexAtExit(atExit);
        return;
    }
    if (command == "clear") {
        clearCapturedData();
        return;
    }
    if (command == "save") {
        if (nrhs != 2 || !mxIsChar(prhs[1])) {
            mexErrMsgIdAndTxt("pcode:trace:Usage", "Usage: pcode_record_trace('save', path)");
        }
        saveRecords(prhs[1]);
        return;
    }
    if (command == "stop") {
        uninstall();
        if (mexIsLocked()) {
            mexUnlock();
        }
        return;
    }
    if (command == "status") {
        if (nlhs > 1) {
            mexErrMsgIdAndTxt("pcode:trace:Usage", "status returns at most one output.");
        }
        const char* fields[] = {"installed", "recordCount", "permutationCount",
                                "callbackRva", "captureFailed"};
        mxArray* status = mxCreateStructMatrix(1, 1, 5, fields);
        mxSetField(status, 0, "installed", mxCreateLogicalScalar(gInstalled));
        {
            std::lock_guard<std::mutex> lock(gMutex);
            mxSetField(status, 0, "recordCount",
                       mxCreateDoubleScalar(static_cast<double>(gRecords.size())));
            mxSetField(status, 0, "permutationCount",
                       mxCreateDoubleScalar(static_cast<double>(gPermutationEvents.size())));
            char callbackText[32]{};
            std::snprintf(callbackText, sizeof(callbackText), "0x%llX",
                          static_cast<unsigned long long>(gObservedCallbackRva));
            mxSetField(status, 0, "callbackRva", mxCreateString(callbackText));
        }
        mxSetField(status, 0, "captureFailed", mxCreateLogicalScalar(gCaptureFailed));
        if (nlhs == 1) {
            plhs[0] = status;
        } else {
            mxDestroyArray(status);
        }
        return;
    }
    mexErrMsgIdAndTxt("pcode:trace:BadCommand", "Unknown command '%s'.", command.c_str());
}

