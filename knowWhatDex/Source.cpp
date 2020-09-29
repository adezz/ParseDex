#include "MyDex.h"

int readUnsignedLeb128(u1** pStream) {
	u1* ptr = *pStream;
	int result = *(ptr++);
	if (result > 0x7f) {
		int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	
	*pStream = ptr;
	return result;
}

// 读取dex文件，存入内存中
void MyReadDexFile(PVOID* pDexFile){
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

// 打印DexHeader头
void getDexHeader(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	pDexHeader = (DexHeader*)pDexFile;
	
	printf("u1  magic[8] : %x", *(PDWORD)pDexHeader->magic);
	printf("%x\n", *(PDWORD)(pDexHeader->magic + 4));
	printf("u4  checksum : %x", pDexHeader->checksum);
	printf("%x", (PDWORD)(&pDexHeader->checksum +4));
	printf("%x", (PDWORD)(&pDexHeader->checksum + 8));
	printf("%x", (PDWORD)(&pDexHeader->checksum + 0XC));
	printf("%x\n", (PDWORD)(&pDexHeader->checksum + 0XF));
	printf("u1  signature : %x\n", pDexHeader->signature);
	printf("u4  fileSize : %x\n", pDexHeader->fileSize);
	printf("u4  headerSize : %x\n", pDexHeader->headerSize);
	printf("u4  endianTag : %x\n", pDexHeader->endianTag);
	printf("u4  linkOff : %x\n", pDexHeader->linkOff);
	printf("u4  mapOff : %x\n", pDexHeader->mapOff);
	printf("u4  stringIdsSize; : %x\n", pDexHeader->stringIdsSize);
	printf("u4  stringIdsOff : %x\n", pDexHeader->stringIdsOff);
	printf("u4  typeIdsSize : %x\n", pDexHeader->typeIdsSize);
	printf("u4  typeIdsOff : %x\n", pDexHeader->typeIdsOff);
	printf("u4  protoIdsSize : %x\n", pDexHeader->protoIdsSize);
	printf("u4  protoIdsOff : %x\n", pDexHeader->protoIdsOff);
	printf("u4  fieldIdsSize : %x\n", pDexHeader->fieldIdsSize);
	printf("u4  fieldIdsOff : %x\n", pDexHeader->fieldIdsOff);
	printf("u4  methodIdsSize : %x\n", pDexHeader->methodIdsSize);
	printf("u4  methodIdsOff : %x\n", pDexHeader->methodIdsOff);
	printf("u4  classDefsSize : %x\n", pDexHeader->classDefsSize);
	printf("u4  classDefsOff : %x\n", pDexHeader->classDefsOff);
	printf("u4  dataSize : %x\n", pDexHeader->dataSize);
	printf("u4  dataOff : %x\n", pDexHeader->dataOff);
	printf("\n");
}

// 遍历dex文件中的字符串区域
void getDexStringId(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	DexStringId* pDexStringId = NULL;
	pDexHeader = (DexHeader*)pDexFile;
	DWORD dwStringIdSize = pDexHeader->stringIdsSize;
	for (DWORD i = 0; i < dwStringIdSize; i++){
		pDexStringId = (DexStringId*)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4*i);
		// 首先pDexStringId的第一个字节是接下来要打印的字符串的长度
		printf("string[%d]: %s\n", i, (PCHAR)((PBYTE)pDexFile + *(PDWORD)pDexStringId + 1));
	}
	printf("\n");
}

// 打印dex中用到的类的类型名称
void getDexTypeId(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	DexStringId* pDexStringId = NULL;
	DexTypeId* pDexTypeId = NULL;

	pDexHeader = (DexHeader*)pDexFile;

	DWORD dwStringIdSize = pDexHeader->stringIdsSize;
	DWORD dwTypeIdSize = pDexHeader->typeIdsSize; // 获取类型的数量
	
	pDexTypeId = (DexTypeId*)((PBYTE)pDexFile + (DWORD)pDexHeader->typeIdsOff); //拿到TypeId位置的地址
	
	for (DWORD i = 0; i < dwTypeIdSize; i++){	
		pDexStringId = (DexStringId*)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * (DWORD)pDexTypeId[i].descriptorIdx);
		// 首先pDexStringId的第一个字节是接下来要打印的字符串的长度，那么就是从第二个字节开始
		printf("type[%d] data: %s\n", i, (PCHAR)((PBYTE)pDexFile + *(PDWORD)pDexStringId + 1));
		
	}
	printf("\n");
	
}

// 打印原型列表
void getDexProtoId(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	DexStringId* pDexStringId = NULL;
	DexTypeId* pDexTypeId = NULL;
	DexProtoId* pDexProtoId = NULL;
	DexTypeList* pDexTypeList = NULL;
	
	pDexHeader = (DexHeader*)pDexFile;
	// pDexStringId = (DexStringId*)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff);
	pDexTypeId = (DexTypeId*)((PBYTE)pDexFile + (DWORD)pDexHeader->typeIdsOff); //拿到TypeId位置的地址

	DWORD dwProtoIdSize = pDexHeader->protoIdsSize;

	for (DWORD i = 0;i<dwProtoIdSize;i++){
		pDexProtoId = (DexProtoId*)((PBYTE)pDexFile + (DWORD)pDexHeader->protoIdsOff + 12*i);

		// shortyIdx
		pDexStringId = (DexStringId*)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexProtoId->shortyIdx);
		printf("string[%d]: %s", i, (PCHAR)((PBYTE)pDexFile + *(PDWORD)pDexStringId + 1));
		
		// returnTypeIdx
		// 首先pDexStringId的第一个字节是接下来要打印的字符串的长度，那么就是从第二个字节开始
		printf(" %s", (PCHAR)((PBYTE)pDexFile + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff
			+ 4 * (DWORD)pDexTypeId[pDexProtoId->returnTypeIdx].descriptorIdx) + 1));
		
		// parametersOff		
		if (pDexProtoId->parametersOff){
			pDexTypeList = (DexTypeList*)((PBYTE)pDexFile + pDexProtoId->parametersOff);
			for (DWORD dwDexTypeListSize = 0; dwDexTypeListSize < pDexTypeList->size; dwDexTypeListSize++){
				//printf(" %s", (PCHAR)((PBYTE)pDexFile + *(PDWORD)((DexStringId*)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff 
				// + 4 * (pDexTypeList->list[dwDexTypeListSize].typeIdx))) + 1));
				printf(" parameters_stringIndex: %x", dwDexTypeListSize, pDexTypeList->list[dwDexTypeListSize].typeIdx);
			}
		}
		else{
			printf(" 0");
		}
		printf("\n");
	}	
	printf("\n");
}

// 打印dex中定义的所有字段的信息，指明了字段所在的类，字段的类型以及字段名称
void getDexFieldId(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	DexStringId* pDexStringId = NULL;
	DexTypeId* pDexTypeId = NULL;
	DexFieldId* pDexFieldId = NULL;

	pDexHeader = (DexHeader*)pDexFile;
	pDexTypeId = (DexTypeId*)((PBYTE)pDexFile + pDexHeader->typeIdsOff);
	pDexFieldId = (DexFieldId*)((PBYTE)pDexFile + pDexHeader->fieldIdsOff);
	pDexStringId = (DexStringId*)((PBYTE)pDexFile + pDexHeader->stringIdsOff);
	
	DWORD dwFieldIdSize = pDexHeader->fieldIdsSize;
	for (DWORD i = 0;i<dwFieldIdSize;i++){
		// 打印当前字段所在的类
		printf("字段所在类: %s", (PCHAR)((PBYTE)pDexFile 
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexTypeId[pDexFieldId[i].classIdx].descriptorIdx)));
		
		// 打印当前字段的类型
		printf(" 字段的类型: %s", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexTypeId[pDexFieldId[i].typeIdx].descriptorIdx)));

		// 打印当前字段的名称
		printf(" 字段的名称: %s", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexFieldId->nameIdx)));
			
		printf("\n");
	}
}

// MethodId描述Dex文件中所有的方法, 指明了方法所在的类、方法的声明以及方法名字
void getDexMethodId(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	DexStringId* pDexStringId = NULL;
	DexTypeId* pDexTypeId = NULL;
	DexProtoId* pDexProtoId = NULL;
	DexFieldId* pDexFieldId = NULL;
	DexMethodId* pDexMethodId = NULL;

	pDexHeader = (DexHeader*)pDexFile;
	pDexTypeId = (DexTypeId*)((PBYTE)pDexFile + pDexHeader->typeIdsOff);
	pDexStringId = (DexStringId*)((PBYTE)pDexFile + pDexHeader->stringIdsOff);
	pDexProtoId = (DexProtoId*)((PBYTE)pDexFile + pDexHeader->protoIdsOff);
	pDexMethodId = (DexMethodId*)((PBYTE)pDexFile + pDexHeader->methodIdsOff);

	DWORD dwFieldIdSize = pDexHeader->fieldIdsSize;

	/*
		u2  classIdx;			索引值指向 type_ids ，表示类的类型
		u2  protoIdx;           索引值指向 proto_ids ，表示方法声明
		u4  nameIdx;            索引值指向 string_ids ，表示方法名
	*/
	for (DWORD i = 0; i<dwFieldIdSize; i++){
		// 打印 类的类型
		printf("方法所在类: %s", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexTypeId[pDexMethodId[i].classIdx].descriptorIdx)));
		
		// 打印 方法声明类型
		printf(" 方法的类型: %s", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexProtoId[pDexMethodId[i].protoIdx].shortyIdx)));

		// 打印 方法名
		printf(" 方法的名称: %s", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexMethodId->nameIdx)));

		printf("\n");
	}
	printf("\n");
}

// Class_def表示了类的所有信息
void getClassdef(PVOID pDexFile){
	DexHeader* pDexHeader = NULL;
	DexStringId* pDexStringId = NULL;
	DexTypeId* pDexTypeId = NULL;
	DexProtoId* pDexProtoId = NULL;
	DexFieldId* pDexFieldId = NULL;
	DexMethodId* pDexMethodId = NULL;
	DexClassDef* pDexClassDef = NULL;
	DexTypeList* pDexTypeList = NULL;
	DexClassData* pDexClassData = NULL;
	DexClassDataHeader* pDexClassDataHeader = NULL;
	DexField* pDexField = NULL;
	DexMethod* pDexMethod = NULL;
	DexCode* pDexCode = NULL;

	pDexHeader = (DexHeader*)pDexFile;
	pDexTypeId = (DexTypeId*)((PBYTE)pDexFile + pDexHeader->typeIdsOff);
	pDexStringId = (DexStringId*)((PBYTE)pDexFile + pDexHeader->stringIdsOff);
	pDexProtoId = (DexProtoId*)((PBYTE)pDexFile + pDexHeader->protoIdsOff);
	pDexMethodId = (DexMethodId*)((PBYTE)pDexFile + pDexHeader->methodIdsOff);
	pDexClassDef = (DexClassDef*)((PBYTE)pDexFile + pDexHeader->classDefsOff);
	pDexClassData = (DexClassData*)((PBYTE)pDexFile + pDexClassDef->classDataOff);
	pDexClassDataHeader = (DexClassDataHeader*)&pDexClassData->header;
	u1* pTemp = (u1*)pDexClassData;
	
	/*
	struct DexClassDef {
		u4  classIdx;           索引值指向 type_ids ，表示类的类型
		u4  accessFlags;		访问标识符 对应的访问权限
		u4  superclassIdx;      索引值指向 type_ids ，表示类的父类的类型 
		u4  interfacesOff;      索引值指向 DexTypeList 的偏移量，表示接口信息 
		u4  sourceFileIdx;      索引值指向 string_ids ，表示源文件名称 
		u4  annotationsOff;     注解信息
		u4  classDataOff;       索引值指向 DexClassData 的偏移量，表示类的数据部分 
		u4  staticValuesOff;    索引值指向 DexEncodedArray 的偏移量，表示类的静态数据
	};*/
	DWORD dwDexClassDefSize = pDexHeader->classDefsSize;
	DWORD dwDexTypeListSize = 0;
	for (DWORD i = 0; i < dwDexClassDefSize; i++){

		printf("类: %s\n", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexTypeId[pDexClassDef[i].classIdx].descriptorIdx)));
		
		printf("访问权限: %x\n", pDexClassDef->accessFlags);
		
		printf("父类: %s\n", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexTypeId[pDexClassDef[i].superclassIdx].descriptorIdx)));
		
		pDexTypeList = (DexTypeList*)((PBYTE)pDexFile + pDexClassDef->interfacesOff);

		if (pDexClassDef->interfacesOff){
			pDexTypeList = (DexTypeList*)((PBYTE)pDexFile + pDexClassDef->interfacesOff);
			printf("接口: %s", (PCHAR)((PBYTE)pDexFile
				+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexTypeId[pDexTypeList->list->typeIdx].descriptorIdx)));
		}
		else{
			printf("接口: 无");
		}

		printf("源文件: %s\n", (PCHAR)((PBYTE)pDexFile
			+ 1 + *(PDWORD)((PBYTE)pDexFile + (DWORD)pDexHeader->stringIdsOff + 4 * pDexClassDef[i].sourceFileIdx)));
		
		printf("注解: %s\n", pDexClassDef[i].annotationsOff);

		/*
		pDexClassData解析 它包含了一个类的核心数据
		
		struct DexClassData {
			DexClassDataHeader header;
			DexField*          staticFields;
			DexField*          instanceFields;
			DexMethod*         directMethods;
			DexMethod*         virtualMethods;
		};*/

		// 先解析pDexClassData中的header，四个字段读取出来的是LEB128 类型
		DWORD staticFieldsSize;
		DWORD instanceFieldsSize;
		DWORD directMethodsSize;
		DWORD virtualMethodsSize;
		DWORD dwIndex = 0;
		DWORD dwTempIndex = 0;
		DWORD dwCodeOff = 0;

		staticFieldsSize = readUnsignedLeb128(&pTemp);
		instanceFieldsSize = readUnsignedLeb128(&pTemp);
		directMethodsSize = readUnsignedLeb128(&pTemp);
		virtualMethodsSize = readUnsignedLeb128(&pTemp);
		
		printf("staticFieldsSize: %x\n", staticFieldsSize);
		printf("instanceFieldsSize: %x\n", instanceFieldsSize);
		printf("directMethodsSize: %x\n", directMethodsSize);
		printf("virtualMethodsSize: %x\n", virtualMethodsSize);
		
		for (DWORD j = 0;j<staticFieldsSize;j++){
			dwTempIndex = readUnsignedLeb128(&pTemp); //差值
			dwIndex += dwTempIndex; //原值
			printf("staticFields[%d].filed_idx_diff: %x\n", j,dwIndex);
			printf("staticFields[%d].accessFlags: %x\n",j, readUnsignedLeb128(&pTemp));
		}

		dwIndex = 0;
		for (DWORD k = 0; k<instanceFieldsSize; k++){
			dwTempIndex = readUnsignedLeb128(&pTemp); //差值
			dwIndex += dwTempIndex; //原值
			printf("instanceFieldsSize[%d].filed_idx_diff: %x\n", k,dwIndex);
			dwCodeOff = readUnsignedLeb128(&pTemp);
			printf("staticFields[%d].accessFlags: %x\n", k, readUnsignedLeb128(&pTemp));
		}

		dwIndex = 0;
		for (DWORD l = 0; l<directMethodsSize; l++){
			dwTempIndex = readUnsignedLeb128(&pTemp); //差值
			dwIndex += dwTempIndex; //原值
			printf("directMethodsSize[%d].filed_idx_diff: %x\n", l, dwIndex);
			printf("directMethodsSize[%d].accessFlags: %x\n", l, readUnsignedLeb128(&pTemp));
			dwCodeOff = readUnsignedLeb128(&pTemp);
			printf("directMethodsSize[%d].code_off: %x\n", l, dwCodeOff);
			//开始解析DexCode
			/*
			struct DexCode {
				u2  registersSize;  // 寄存器个数
				u2  insSize;        // 参数的个数
				u2  outsSize;       // 调用其他方法时使用的寄存器个数
				u2  triesSize;      // try/catch 语句个数
				u4  debugInfoOff;   // debug 信息的偏移量
				u4  insnsSize;      // 指令集的个数
				u2  insns[1];       // 指令集
			}*/
			pDexCode = (DexCode*)((PBYTE)pDexFile + dwCodeOff);
			printf("registersSize: %x\n", pDexCode->registersSize);			
			printf("insSize: %x\n", pDexCode->insSize);
			printf("outsSize: %x\n", pDexCode->outsSize);
			printf("triesSize: %x\n", pDexCode->triesSize);
			printf("debugInfoOff: %x\n", pDexCode->debugInfoOff);
			printf("insnsSize: %x\n", pDexCode->insnsSize);
			for (DWORD n = 0; n < pDexCode->insnsSize; n++){
				printf("%04x ", *((PWORD)pDexCode + n));
			}
			printf("\n");
		}
		
		dwIndex = 0;
		for (DWORD m = 0; m<virtualMethodsSize; m++){
			dwTempIndex = readUnsignedLeb128(&pTemp); //差值
			dwIndex += dwTempIndex; //原值
			printf("virtualMethodsSize[%d].filed_idx_diff: %x\n", m, dwIndex);
			printf("virtualMethodsSize[%d].accessFlags: %x\n", m, readUnsignedLeb128(&pTemp));
			dwCodeOff = readUnsignedLeb128(&pTemp);
			printf("virtualMethodsSize[%d].code_off: %x\n", m, dwCodeOff);
			pDexCode = (DexCode*)((PBYTE)pDexFile + dwCodeOff);
			printf("registersSize: %x\n", pDexCode->registersSize);
			printf("insSize: %x\n", pDexCode->insSize);
			printf("outsSize: %x\n", pDexCode->outsSize);
			printf("triesSize: %x\n", pDexCode->triesSize);
			printf("debugInfoOff: %x\n", pDexCode->debugInfoOff);
			printf("insnsSize: %x\n", pDexCode->insnsSize);
			for (DWORD o = 0; o < pDexCode->insnsSize; o++){
				printf("%04x ", *((PWORD)pDexCode + o));
			}
			printf("\n");
		}
		
		printf("\n");
	}
}


int main(){
	PVOID pDexFile = NULL;

	//0、读取文件到内存中进行存储
	MyReadDexFile(&pDexFile);
	
	//1、解析文件头 大小为0x70
	getDexHeader(pDexFile);
	
	//2、解析string_ids数据结构
	getDexStringId(pDexFile);

	//3、解析type_ids数据结构
	getDexTypeId(pDexFile);

	//4、解析proto_ids数据结构
	getDexProtoId(pDexFile);	

	//5、解析field_ids数据结构
	getDexFieldId(pDexFile);
	
	//6、解析methoid_ids数据结构
	getDexMethodId(pDexFile);
	
	//7、解析classdef数据结构
	getClassdef(pDexFile);
	
	return 0;
}