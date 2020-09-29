#pragma once

#include<stdint.h>
#include<Windows.h>
#include <cstdio>

#define dexFileName "C:\\Users\\dell\\Desktop\\Hello.dex"

typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;

enum {
	ACC_PUBLIC = 0x00000001,       // class, field, method, ic
	ACC_PRIVATE = 0x00000002,       // field, method, ic
	ACC_PROTECTED = 0x00000004,       // field, method, ic
	ACC_STATIC = 0x00000008,       // field, method, ic
	ACC_FINAL = 0x00000010,       // class, field, method, ic
	ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
	ACC_SUPER = 0x00000020,       // class (not used in Dalvik)
	ACC_VOLATILE = 0x00000040,       // field
	ACC_BRIDGE = 0x00000040,       // method (1.5)
	ACC_TRANSIENT = 0x00000080,       // field
	ACC_VARARGS = 0x00000080,       // method (1.5)
	ACC_NATIVE = 0x00000100,       // method
	ACC_INTERFACE = 0x00000200,       // class, ic
	ACC_ABSTRACT = 0x00000400,       // class, method, ic
	ACC_STRICT = 0x00000800,       // method
	ACC_SYNTHETIC = 0x00001000,       // field, method, ic
	ACC_ANNOTATION = 0x00002000,       // class, ic (1.5)
	ACC_ENUM = 0x00004000,       // class, field, ic (1.5)
	ACC_CONSTRUCTOR = 0x00010000,       // method (Dalvik only)
	ACC_DECLARED_SYNCHRONIZED = 0x00020000,       // method (Dalvik only)
	ACC_CLASS_MASK = (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),

	ACC_INNER_CLASS_MASK = (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),

	ACC_FIELD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),

	ACC_METHOD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
	| ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
	| ACC_DECLARED_SYNCHRONIZED),
		
};

struct DexHeader {
	u1  magic[8];           /* includes version number */
	u4  checksum;           /* adler32 checksum */
	u1  signature[20]; /* SHA-1 hash */
	u4  fileSize;           /* length of entire file */
	u4  headerSize;         /* offset to start of next section */
	u4  endianTag;
	u4  linkSize;
	u4  linkOff;
	u4  mapOff;
	u4  stringIdsSize;
	u4  stringIdsOff;
	u4  typeIdsSize;
	u4  typeIdsOff;
	u4  protoIdsSize;
	u4  protoIdsOff;
	u4  fieldIdsSize;
	u4  fieldIdsOff;
	u4  methodIdsSize;
	u4  methodIdsOff;
	u4  classDefsSize;
	u4  classDefsOff;
	u4  dataSize;
	u4  dataOff;
};

struct DexMapItem {
	u2 type;              /* type code (see kDexType* above) */
	u2 unused;
	u4 size;              /* count of items of the indicated type */
	u4 offset;            /* file offset to the start of data */
};

struct DexMapList {
	u4  size;               /* #of entries in list */
	DexMapItem list[1];     /* entries */
};

struct DexStringId {
	u4 stringDataOff;
};

struct DexTypeId {
	u4  descriptorIdx;
};

struct DexProtoId {
	u4  shortyIdx;          /* shortyIdx : ָ�� string_ids ����ʾ�����������ַ��� */
	u4  returnTypeIdx;      /* returnTypeIdx : ָ�� type_ids ����ʾ�����ķ������� */
	u4  parametersOff;      /* parametersOff �� ���������б��ƫ��������ƫ��+dexFile�ĳ�ʼ�ط�ָ��һ��DexTypeList�Ľṹ�� */
};

struct DexTypeItem {
	u2  typeIdx;            //DexTypeId�е������±�
};
//rect-mapped "type_list".
struct DexTypeList {
	u4  size;               //DexTypeItem�ĸ���
	DexTypeItem list[1];    //DexTypeItem�䳤����
};

struct DexFieldId {
	u2  classIdx;           /* ����ֵָ�� type_ids ����ʾ�ֶ����������Ϣ */
	u2  typeIdx;            /* ����ֵָ�� type_ids ����ʾ�ֶε�������Ϣ */
	u4  nameIdx;            /* ����ֵָ�� string_ids ����ʾ�ֶ����� */
};

struct DexMethodId {
	u2  classIdx;           /* ����ֵָ�� type_ids ����ʾ������� */
	u2  protoIdx;           /* ����ֵָ�� proto_ids ����ʾ�������� */
	u4  nameIdx;            /* ����ֵָ�� string_ids ����ʾ������ */
};

// ���������Ϣ ��Сռ32�ֽ�
struct DexClassDef {	
	u4  classIdx;           /* ����ֵָ�� type_ids ����ʾ������� */
	u4  accessFlags;		/* ���ʱ�ʶ�� ��Ӧ�ķ���Ȩ�� */
	u4  superclassIdx;      /* ����ֵָ�� type_ids ����ʾ��ĸ�������� */
	u4  interfacesOff;      /* ����ֵָ�� DexTypeList ��ƫ��������ʾ�ӿ���Ϣ */
	u4  sourceFileIdx;      /* ����ֵָ�� string_ids ����ʾԴ�ļ����� */
	u4  annotationsOff;     /* ע����Ϣ */
	u4  classDataOff;       /* ����ֵָ�� DexClassData ��ƫ��������ʾ������ݲ��� */
	u4  staticValuesOff;    /* ����ֵָ�� DexEncodedArray ��ƫ��������ʾ��ľ�̬����*/
};

struct DexField { /* DexField��DexMethod����Uleb128����*/
	u4 fieldIdx;    /* index to a field_id_item */
	u4 accessFlags;
};

struct DexMethod { /* DexField��DexMethod����Uleb128����*/
	u4 methodIdx;    /* index to a method_id_item */
	u4 accessFlags;
	u4 codeOff;      /* ָ��DexCode�ṹ���ƫ��ֵ���洢��Ӧ��������ϸ��Ϣ�Լ����е�ָ���ƫ��ֵ */
};

struct DexCode {
	u2  registersSize;  // �Ĵ�������
	u2  insSize;        // �����ĸ���
	u2  outsSize;       // ������������ʱʹ�õļĴ�������
	u2  triesSize;      // try/catch ������
	u4  debugInfoOff;   // debug ��Ϣ��ƫ����
	u4  insnsSize;      // ָ��ĸ���
	u2  insns[1];       // ָ�
	/* followed by optional u2 padding */  // 2 �ֽڣ����ڶ���
	/* followed by try_item[triesSize] */
	/* followed by uleb128 handlersSize */
	/* followed by catch_handler_item[handlersSize] */
};

/* �����������ֶκͷ�������Ŀ ��Сռ16�ֽ�*/
struct DexClassDataHeader {
	u4 staticFieldsSize; // ��̬�ֶθ���
	u4 instanceFieldsSize; // ʵ���ֶθ���
	u4 directMethodsSize; // ֱ�ӷ�������
	u4 virtualMethodsSize; // �鷽������
	/*
	�ڶ�ȡ��ʱ��Ҫע������������� LEB128 ���͡�����һ�ֿɱ䳤�����ͣ�ÿ�� LEB128 �� 1~5 ���ֽ���ɣ�ÿ���ֽ�ֻ�� 7 ����Чλ��
	�����һ���ֽڵ����λΪ 1����ʾ��Ҫ����ʹ�õ� 2 ���ֽڣ�����ڶ����ֽ����λΪ 1����ʾ��Ҫ����ʹ�õ������ֽڣ�
	�������ƣ�ֱ�����һ���ֽڵ����λΪ 0������ 5 ���ֽڡ����� LEB128 ���⣬�����޷������� ULEB128��
	*/
};

/* ���������������Сռ32�ֽ�*/
struct DexClassData {
	DexClassDataHeader header;
	DexField*		staticFields; // ��̬�ֶ� 
	DexField*		instanceFields; // ʵ���ֶ�
	DexMethod*	directMethods; // ֱ�ӷ���
	DexMethod*	virtualMethods; // �鷽��
};

class MyDex
{
public:
	MyDex();
	void MyReadDexFile(PVOID* pDexFile);
	void getDexHeader();
	void getDexStringId();
	void getDexTypeId();
	void getDexProtoId();
	void getDexFieldId();
	void getDexMethodId();
	~MyDex();
private:
	PVOID pDexFile;
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
};

