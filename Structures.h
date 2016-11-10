#pragma once
struct Function {
	/*
		Holds information about a function import. This will be in a struct DLL.functions vector.
	*/
	std::string name;
	LPCSTR ordinal;
	HANDLE handle;
	uintptr_t locationInIAT;
	uintptr_t locationInOriginalIAT;
};


struct DLL {
	/*
		Holds information about a DLL import.
	*/
	std::string name;
	HMODULE handle;
	std::vector<Function> functions;
};


class Address {
	uintptr_t start;

public:
	Address() { }
	void setStart(uintptr_t addr) {
		start = addr;
	}

	BYTE* operator[](BYTE* addr) {
		return start + addr;
	}

	BYTE* operator[](int addr) {
		return (BYTE*)(start + (uintptr_t)addr);
	}

	uintptr_t os(int addr) {
		return start + addr;
	}
};


class FileDirectory {
	/*
		Holds the information about input and output file directories.
	*/
public:
	std::wstring executableName;
	std::wstring executableDirectory;
	std::wstring outputDirectory;

	std::wstring executablePath() {
		return executableDirectory + executableName;
	}

	std::wstring binaryPath() {
		std::wstring binaryName = executableName;
		binaryName = fileNameWithoutExtension() + std::wstring(L".bin");
		return outputDirectory + binaryName;
	}

	std::wstring importMacroPath() {
		return outputDirectory + fileNameWithoutExtension() + std::wstring(L"_importMacros.txt");
	}

	std::wstring importStringPath() {
		return outputDirectory + fileNameWithoutExtension() + std::wstring(L"_importStrings.txt");
	}

	std::wstring binaryRsrcPath() {
		std::wstring binaryName = executableName;
		binaryName = fileNameWithoutExtension() + std::wstring(L"_rsrc.bin");
		return outputDirectory + binaryName;
	}

	std::wstring rsrcRelocationsPath() {
		std::wstring binaryName = executableName;
		binaryName = fileNameWithoutExtension() + std::wstring(L"_rsrcRelocations.txt");
		return outputDirectory + binaryName;
	}

private:
	std::wstring fileNameWithoutExtension() {
		std::wstring fileName = executableName;
		fileName = fileName.substr(0, executableName.rfind(L".exe"));
		return fileName;
	}
};