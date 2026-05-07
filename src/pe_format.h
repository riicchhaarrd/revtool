#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct DataDirectoryEntry {
    std::string name;
    uint32_t rva = 0;
    uint32_t size = 0;
};

struct PEHeader {
    uint32_t peOffset = 0;
    uint32_t signature = 0;
    uint16_t machine = 0;
    uint16_t numberOfSections = 0;
    uint32_t timeDateStamp = 0;
    uint32_t pointerToSymbolTable = 0;
    uint32_t numberOfSymbols = 0;
    uint16_t sizeOfOptionalHeader = 0;
    uint16_t characteristics = 0;
    uint16_t optionalMagic = 0;
    uint8_t  majorLinkerVersion = 0;
    uint8_t  minorLinkerVersion = 0;
    uint32_t sizeOfCode = 0;
    uint32_t sizeOfInitializedData = 0;
    uint32_t sizeOfUninitializedData = 0;
    uint32_t addressOfEntryPoint = 0;
    uint32_t baseOfCode = 0;
    uint32_t baseOfData = 0;
    uint32_t imageBase = 0;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint16_t majorOSVersion = 0;
    uint16_t minorOSVersion = 0;
    uint16_t majorImageVersion = 0;
    uint16_t minorImageVersion = 0;
    uint16_t majorSubsystemVersion = 0;
    uint16_t minorSubsystemVersion = 0;
    uint32_t sizeOfImage = 0;
    uint32_t sizeOfHeaders = 0;
    uint32_t checksum = 0;
    uint16_t subsystem = 0;
    uint16_t dllCharacteristics = 0;
    uint32_t sizeOfStackReserve = 0;
    uint32_t sizeOfStackCommit = 0;
    uint32_t sizeOfHeapReserve = 0;
    uint32_t sizeOfHeapCommit = 0;
    uint32_t loaderFlags = 0;
    uint32_t numberOfRvaAndSizes = 0;
    std::vector<DataDirectoryEntry> dataDirectories;
};
