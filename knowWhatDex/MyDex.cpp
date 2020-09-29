#include "MyDex.h"

MyDex::MyDex()
{
	this->MyReadDexFile(&this->pDexFile);
	this->pDexHeader = (DexHeader*)this->pDexFile;
	this->pDexStringId = NULL;
	this->pDexTypeId = NULL;
	this->pDexProtoId = NULL;
	this->pDexFieldId = NULL;
	this->pDexMethodId = NULL;
}

MyDex::~MyDex()
{
}

void MyDex::MyReadDexFile(PVOID* pDexFile){
	FILE* pFile;
	DWORD dwDexFileSize;
	fopen_s(&pFile, dexFileName, "rb");
	//读取文件
	fseek(pFile, 0, SEEK_END);
	dwDexFileSize = ftell(pFile);
	//重新把File指针指向文件的开头
	fseek(pFile, 0, SEEK_SET);
	//开辟新空间
	*pDexFile = (PVOID)malloc(dwDexFileSize);
	//内存清零
	memset(*pDexFile, 0, dwDexFileSize);
	//读取到内存缓冲区
	fread(*pDexFile, dwDexFileSize, 1, pFile);// 一次读入dwDexFileSize个字节，重复1次
	//关闭文件句柄
	fclose(pFile);
}

void MyDex::getDexHeader(){
	printf("u1  magic[8] : %x", *(PDWORD)this->pDexHeader->magic);
	printf("%x\n", *(PDWORD)(this->pDexHeader->magic + 4));
	printf("u4  checksum : %x", this->pDexHeader->checksum);
	printf("%x", (PDWORD)(&this->pDexHeader->checksum + 4));
	printf("%x", (PDWORD)(&this->pDexHeader->checksum + 8));
	printf("%x", (PDWORD)(&this->pDexHeader->checksum + 0XC));
	printf("%x\n", (PDWORD)(&this->pDexHeader->checksum + 0XF));
	printf("u1  signature : %x\n", this->pDexHeader->signature);
	printf("u4  fileSize : %x\n", this->pDexHeader->fileSize);
	printf("u4  headerSize : %x\n", this->pDexHeader->headerSize);
	printf("u4  endianTag : %x\n", this->pDexHeader->endianTag);
	printf("u4  linkOff : %x\n", this->pDexHeader->linkOff);
	printf("u4  mapOff : %x\n", this->pDexHeader->mapOff);
	printf("u4  stringIdsSize; : %x\n", this->pDexHeader->stringIdsSize);
	printf("u4  stringIdsOff : %x\n", this->pDexHeader->stringIdsOff);
	printf("u4  typeIdsSize : %x\n", this->pDexHeader->typeIdsSize);
	printf("u4  typeIdsOff : %x\n", this->pDexHeader->typeIdsOff);
	printf("u4  protoIdsSize : %x\n", this->pDexHeader->protoIdsSize);
	printf("u4  protoIdsOff : %x\n", this->pDexHeader->protoIdsOff);
	printf("u4  fieldIdsSize : %x\n", this->pDexHeader->fieldIdsSize);
	printf("u4  fieldIdsOff : %x\n", this->pDexHeader->fieldIdsOff);
	printf("u4  methodIdsSize : %x\n", this->pDexHeader->methodIdsSize);
	printf("u4  methodIdsOff : %x\n", this->pDexHeader->methodIdsOff);
	printf("u4  classDefsSize : %x\n", this->pDexHeader->classDefsSize);
	printf("u4  classDefsOff : %x\n", this->pDexHeader->classDefsOff);
	printf("u4  dataSize : %x\n", this->pDexHeader->dataSize);
	printf("u4  dataOff : %x\n", this->pDexHeader->dataOff);
	printf("\n");
}
