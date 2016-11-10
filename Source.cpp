/*
	Made this in the summer of 2016.

	A 32-bit executable protector.
	Source.cpp extracts various information about the executable we want to protect, which is then used by the FASM source to make the stub and the final protected executable.
	Source.cpp also maps the executable according to the descriptions in the PE header.
	I need to make it so that the FASM source is automatically generated and ran by a script, it's just a bunch of copy/paste anyway. Not too much burden right now anyhow.
	Also you need to set the location of .rsrc manually as of right now after FASM is compiled. Just look for the .rsrc section and set its location in the PE directories.
	Also the entry point needs to be set manually in the FASM src.
	Also, I'm not handling the TLS section.

	I'm using the TEA(Tiny Encryption Algorithm) because it's very easy to implement, maybe I'll implement this with a proper compression algorithm later to make a packer. But that's a whole different story.
*/

#include <iostream>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include <ImageHlp.h>
#include <vector>
#include <string>
#include <array>
#include "Structures.h"
#include "TEA.h"

using namespace std;

const unsigned int FILE_SIZE = 11935744;
unsigned char* executableRawData[FILE_SIZE];


class PEHeader {
	/*
		Extracts information about the PE32 header of the given executable.
	*/
public:
	std::vector<DLL> dlls; //DLLs imported by the PE32.
	std::vector<_IMAGE_SECTION_HEADER> sections; //.Sections of the PE32.
	DWORD virtualAddressOfResourceSection;
	_IMAGE_NT_HEADERS header;
	Address startAddr; //The start address of the raw executable loaded in our memory.

	PEHeader() { }


	void extract(uintptr_t addr) { //Should this be called from the constructor? I wanted to make it more obvious anyway.
		startAddr.setStart(addr);
		extractPE();
	}


	void extractPE() {
		uintptr_t PEStart = findPESignature();

		header = *(_IMAGE_NT_HEADERS*)PEStart;

		uintptr_t sectionAddr = PEStart + sizeof(_IMAGE_NT_HEADERS);

		for (int i = 0; i < header.FileHeader.NumberOfSections; i++) { //Grab all of the sections.
			sections.push_back(*(_IMAGE_SECTION_HEADER*)sectionAddr);
			//std::cout << sections[i].Name << " " << std::hex << sections[i].PointerToRawData << std::endl;
			//std::cout << sections[i].Name << " " << std::hex << sections[i].VirtualAddress << std::endl;
			sectionAddr += sizeof(_IMAGE_SECTION_HEADER);
		}

		virtualAddressOfResourceSection = findResourceSection();
		extractDLLs();
	}
	

	void extractFunctions(IMAGE_IMPORT_DESCRIPTOR dll, uintptr_t sectionStartAddrRaw) {
		uintptr_t selectedFunctionImport = dll.Characteristics + sectionStartAddrRaw;
		uintptr_t selectedFunctionImportIAT = dll.FirstThunk + sectionStartAddrRaw;

		while (true) { //Loop over all functions.
			IMAGE_THUNK_DATA funcThunkData = *(IMAGE_THUNK_DATA*)selectedFunctionImport;
			selectedFunctionImport += sizeof(IMAGE_THUNK_DATA); //Next loop we'll loop over to the next IMAGE_THUNK_DATA.
			if (funcThunkData.u1.Function == NULL) { //Check if we need to exit the looping since there are no more functions to import.
				break;
			}

			Function function;

			if (funcThunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG) { //Check if it's imported by ordinal.
				function.ordinal = MAKEINTRESOURCEA(funcThunkData.u1.Ordinal);
			} else { //else import by name
				IMAGE_IMPORT_BY_NAME* functionImport = (IMAGE_IMPORT_BY_NAME*)(funcThunkData.u1.Function + sectionStartAddrRaw);
				function.name = std::string(functionImport->Name);
				function.ordinal = 0x0;
			}

			function.locationInIAT = selectedFunctionImportIAT;
			function.locationInOriginalIAT = selectedFunctionImportIAT - sectionStartAddrRaw + header.OptionalHeader.ImageBase;
			selectedFunctionImportIAT += sizeof(IMAGE_THUNK_DATA);
			dlls.back().functions.push_back(function); //We assume that `IMAGE_IMPORT_DESCRIPTOR dll` is the last one in the dlls vector.
		}
	}


	void extractDLLs() {
		for (int i = 0; i < header.OptionalHeader.NumberOfRvaAndSizes; i++) { //Loop over directories.
			if (i != IMAGE_DIRECTORY_ENTRY_IMPORT) continue; //We're only interested in the import directory.
			IMAGE_DATA_DIRECTORY directory = header.OptionalHeader.DataDirectory[i];

			uintptr_t sectionStart = 0;
			for (auto &section : sections) { //Calculate the raw address inside our program from the directory.VirtualAddress. (Matches up directory rva with relevant section.
				auto inRange = [](uintptr_t val, uintptr_t low, uintptr_t high) {return val >= low && val < high; };
				if (inRange(directory.VirtualAddress, section.VirtualAddress, section.VirtualAddress + section.Misc.VirtualSize)) { //If the virtual address is in one of the ranges of the section. Range being section.VAAddr to section.VASize... section.VirtualAddress is what the RVA is relative to.
					sectionStart = section.PointerToRawData - section.VirtualAddress + startAddr.os(0);
					break;
				}
			}

			uintptr_t selectedImport = sectionStart + directory.VirtualAddress;
			while (true) { //Loop over all IMAGE_IMPORT_DESCRIPTIORS (dll entries).
				IMAGE_IMPORT_DESCRIPTOR importDLL = *(IMAGE_IMPORT_DESCRIPTOR*)selectedImport;
				selectedImport += sizeof(IMAGE_IMPORT_DESCRIPTOR); //So next time we loop to the next descriptor.
				if (importDLL.Characteristics == NULL) break; //No more import descriptors since the end of them is indicated by an all NULL IMAGE_IMPORT_DESCRIPTOR. 

				DLL dll;
				dll.name = std::string((char*)(importDLL.Name + sectionStart));
				dlls.push_back(dll);

				extractFunctions(importDLL, sectionStart);
			}
		}
	}
	

	DWORD findResourceSection() {
		for (int i = 0; i < header.OptionalHeader.NumberOfRvaAndSizes; i++) { //Loop over directories.
			if (i != IMAGE_DIRECTORY_ENTRY_RESOURCE) continue;
			return header.OptionalHeader.DataDirectory[i].VirtualAddress;
		}

		throw std::runtime_error("No data entry for resources section.");
	}


	uintptr_t findPESignature() {
		std::array<BYTE, 4> PESIG = {0x50, 0x45, 0x00, 0x00};

		uintptr_t pos = 0;
		while (true) {
			if (memcmp(PESIG.data(), startAddr[pos], PESIG.size()) == 0) return startAddr.os(pos);
			pos++;
		}
	}
};


class Payload {
private:
	size_t size;
	HANDLE hFile, hMap;

public:
	uintptr_t entryPoint;
	uintptr_t newImageBase; //The image base of the executable when we map it according to the PE file's descriptions.
	struct rsrcInfo {
		uintptr_t start;
		size_t size;
	} rsrcInfo;

	PEHeader peHeader;
	size_t loadedRange = 0;

	Payload(FileDirectory fileDirectoryInfo, size_t size) :
		size(size)
	{
		peHeader.extract((uintptr_t)&executableRawData[0]);

		newImageBase = mapSections();

		saveImports(fileDirectoryInfo);

		entryPoint = peHeader.header.OptionalHeader.AddressOfEntryPoint + newImageBase;
		CloseHandle(hMap); CloseHandle(hFile);
	}
	

	uintptr_t mapSections() {
		/*
			Maps the sections as they would be mapped by the windows loader, except in our own address space so the stub doesn't have to spned time mapping the sections.
		*/
		newImageBase = (uintptr_t)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //Allocate memory for all sections.
		if (newImageBase == NULL) { throw std::runtime_error("Couldn't virtual alloc for sections: " + GetLastError()); }

		auto writeSection = [](uintptr_t locationToWrite, uintptr_t pointerToRawData, size_t virtualSize) {
			memcpy((void*)locationToWrite, (void*)pointerToRawData, virtualSize);
		};

		for (auto &section : peHeader.sections) {
			//If bss section, write 0 to it and continue.
			if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA || strcmp((char*)&section.Name[0], ".bss") == 0) { 
				memset((LPVOID)(section.VirtualAddress + newImageBase), 0, section.Misc.VirtualSize); continue; 
			}

			//If rsrc section, load it up in its own block of memory and continue(skip writing it.)
			if (section.VirtualAddress == peHeader.virtualAddressOfResourceSection || strcmp((char*)&section.Name[0], ".rsrc") == 0) {
				if (rsrcInfo.start == NULL) {
					rsrcInfo.start = (uintptr_t)VirtualAlloc(NULL, section.Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //Allocate a memory pocket for the rsrc section so we can save it later.
					rsrcInfo.size = section.SizeOfRawData;
					writeSection(rsrcInfo.start, section.PointerToRawData + peHeader.startAddr.os(0), section.SizeOfRawData); //SizeofRawData instead of VirtualSize for rsrc section, because it is read by the OS on disk and not when loaded.
				} else {
					throw std::runtime_error("2 Resource sections?");
				}
				continue;
			} 

			writeSection(section.VirtualAddress + newImageBase, section.PointerToRawData + peHeader.startAddr.os(0), section.Misc.VirtualSize); //last parameter: This needs to be section.SizeOfRawData and if it's less than section.Misc.VirtualSize it needs to be padded with 0s.
			std::cout << "Mapped section " << section.Name << " at " << std::hex << section.VirtualAddress + newImageBase << " size: " << std::hex << section.Misc.VirtualSize << std::endl;
			if (section.Misc.VirtualSize > section.SizeOfRawData) { //Pad section with 0es if VA is bigger than raw data.
				std::cout << "Section virtual size bigger than raw data size, padding difference with zeroes." << std::endl;
				memset((LPVOID)(newImageBase + section.VirtualAddress + section.SizeOfRawData), 0, section.Misc.VirtualSize - section.SizeOfRawData);
			}
			
		}
		loadedRange = peHeader.sections.back().VirtualAddress - peHeader.sections[0].VirtualAddress + peHeader.sections.back().Misc.VirtualSize + 0x1000; //0x1000 to account for first 0x1000 '00' bytes

		return newImageBase;
	}


	void saveImports(FileDirectory fileDirectoryInfo) {
		/*
			Generate 2 include files for FASM that contains a bunch of FASM macros that will load up the functions and DLLs when the stub is executing.
		*/
		int placeHolderNameForOrdinals = 0;
		ofstream outImportMacro(fileDirectoryInfo.importMacroPath());
		ofstream outImportString(fileDirectoryInfo.importStringPath());

		for (auto &dll : peHeader.dlls) {
			std::wstring stemp = std::wstring(dll.name.begin(), dll.name.end());
			dll.handle = GetModuleHandle(stemp.c_str()) ? GetModuleHandle(stemp.c_str()) : LoadLibraryA(dll.name.c_str());
			std::cout << "Loaded: " << dll.name << std::endl;

			outImportString << dll.name << "@ db " << "'" << dll.name << "'" << ", 0" << std::endl;

			if (dll.handle == NULL) {
				throw std::runtime_error("Failed to load DLL " + dll.name);
			}

			for (auto &function : dll.functions) {
				if (function.ordinal != 0x00) { //If ordinal isn't 0, then import by ordinal.
					function.name = std::string(dll.name + std::to_string(placeHolderNameForOrdinals));
					placeHolderNameForOrdinals++;
					function.handle = GetProcAddress(dll.handle, function.ordinal);
					outImportMacro << "    imp " << function.name.c_str() << "@," << function.locationInOriginalIAT << "," << dll.name << "@" << "," << (unsigned int)function.ordinal << std::endl;
					outImportString << function.name << "@ db " << "'" << function.name << "'" << ", 0" << std::endl;
				} else {
					function.handle = GetProcAddress(dll.handle, function.name.c_str());
					outImportMacro << "    imp " << function.name.c_str() << "@," << function.locationInOriginalIAT << "," << dll.name << "@" << "," << 0x00 << std::endl;
					outImportString << function.name << "@ db " << "'" << function.name << "'" << ", 0" << std::endl;
				}

				if (function.handle == NULL) {
					throw std::runtime_error("Failed to load Function " + function.name);
				}
			}
		}
	}

};


size_t loadData(std::wstring fileName) {
	/*
		Loads an executable's raw memory into our address space.
	*/
	HANDLE hFile = CreateFile(fileName.c_str(), FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("Couldn't open handle to file: " + GetLastError());
	}
	auto fileSize = GetFileSize(hFile, NULL);

	DWORD oldProtect = 0;
	auto protectResult = VirtualProtect((LPVOID)&executableRawData[0], fileSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (protectResult == 0) {
		std::cout << GetLastError();
		throw std::runtime_error("Couldn't change page to be executable: " + GetLastError());
	}

	ReadFile(hFile, (LPVOID)&executableRawData[0], fileSize, NULL, NULL);
	CloseHandle(hFile);

	return fileSize;
}


int main() {
	//Describe the output/input file and directories. This is better suited in a .cfg file or as commandline arguments, maybe I'll change it later.
	FileDirectory fileDirectoryInfo;
	fileDirectoryInfo.executableName = std::wstring(L"openttd_real.exe");
	fileDirectoryInfo.executableDirectory = std::wstring(L"C:\\Program Files (x86)\\OpenTTD\\");
	fileDirectoryInfo.outputDirectory = std::wstring(L"C:\\Users\\Ecoste\\Desktop\\Pakcer\\OpenTTDOutput\\");

	auto fileSize = loadData(fileDirectoryInfo.executablePath()); //Load up raw executable data into memory.
	Payload payload(fileDirectoryInfo, FILE_SIZE*5); //Process the raw executable in memory and extract the data we need from it.


	//encrypt the loaded and mapped executable.
	uint8_t key[4] = { 0x11, 0x22, 0x33, 0x44 };
	for (int i = 0; i < payload.loadedRange + 0x2000; i = i+2) {
		encrypt((uint8_t*)(payload.newImageBase + 0x1000 + i), key);
	}

	//save file
	ofstream binaryOut(fileDirectoryInfo.binaryPath(), ios_base::binary);
	binaryOut.write((char*)payload.newImageBase + 0x1000, payload.loadedRange + 0x2000);

	//save .rsrc
	if (payload.rsrcInfo.start != NULL) {
		ofstream rsrcOut(fileDirectoryInfo.binaryRsrcPath(), ios_base::binary);
		rsrcOut.write((char*)payload.rsrcInfo.start, payload.rsrcInfo.size);
	}
	std::cout << "LoadedRange: " << std::hex << payload.loadedRange << std::endl;

	getchar();
}
