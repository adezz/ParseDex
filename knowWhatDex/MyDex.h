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
	u4  shortyIdx;          /* shortyIdx : 指向 string_ids ，表示方法声明的字符串 */
	u4  returnTypeIdx;      /* returnTypeIdx : 指向 type_ids ，表示方法的返回类型 */
	u4  parametersOff;      /* parametersOff ： 方法参数列表的偏移量，该偏移+dexFile的初始地方指向一个DexTypeList的结构体 */
};

struct DexTypeItem {
	u2  typeIdx;            //DexTypeId中的索引下标
};
//rect-mapped "type_list".
struct DexTypeList {
	u4  size;               //DexTypeItem的个数
	DexTypeItem list[1];    //DexTypeItem变长数组
};

struct DexFieldId {
	u2  classIdx;           /* 索引值指向 type_ids ，表示字段所在类的信息 */
	u2  typeIdx;            /* 索引值指向 type_ids ，表示字段的类型信息 */
	u4  nameIdx;            /* 索引值指向 string_ids ，表示字段名称 */
};

struct DexMethodId {
	u2  classIdx;           /* 索引值指向 type_ids ，表示类的类型 */
	u2  protoIdx;           /* 索引值指向 proto_ids ，表示方法声明 */
	u4  nameIdx;            /* 索引值指向 string_ids ，表示方法名 */
};

// 类的所有信息 大小占32字节
struct DexClassDef {	
	u4  classIdx;           /* 索引值指向 type_ids ，表示类的类型 */
	u4  accessFlags;		/* 访问标识符 对应的访问权限 */
	u4  superclassIdx;      /* 索引值指向 type_ids ，表示类的父类的类型 */
	u4  interfacesOff;      /* 索引值指向 DexTypeList 的偏移量，表示接口信息 */
	u4  sourceFileIdx;      /* 索引值指向 string_ids ，表示源文件名称 */
	u4  annotationsOff;     /* 注解信息 */
	u4  classDataOff;       /* 索引值指向 DexClassData 的偏移量，表示类的数据部分 */
	u4  staticValuesOff;    /* 索引值指向 DexEncodedArray 的偏移量，表示类的静态数据*/
};

struct DexField { /* DexField和DexMethod都是Uleb128编码*/
	u4 fieldIdx;    /* index to a field_id_item */
	u4 accessFlags;
};

struct DexMethod { /* DexField和DexMethod都是Uleb128编码*/
	u4 methodIdx;    /* index to a method_id_item */
	u4 accessFlags;
	u4 codeOff;      /* 指向DexCode结构体的偏移值，存储对应方法的详细信息以及其中的指令的偏移值 */
};

struct DexCode {
	u2  registersSize;  // 寄存器个数
	u2  insSize;        // 参数的个数
	u2  outsSize;       // 调用其他方法时使用的寄存器个数
	u2  triesSize;      // try/catch 语句个数
	u4  debugInfoOff;   // debug 信息的偏移量
	u4  insnsSize;      // 指令集的个数
	u2  insns[1];       // 指令集
	/* followed by optional u2 padding */  // 2 字节，用于对齐
	/* followed by try_item[triesSize] */
	/* followed by uleb128 handlersSize */
	/* followed by catch_handler_item[handlersSize] */
};

/* 定义了类中字段和方法的数目 大小占16字节*/
struct DexClassDataHeader {
	u4 staticFieldsSize; // 静态字段个数
	u4 instanceFieldsSize; // 实例字段个数
	u4 directMethodsSize; // 直接方法个数
	u4 virtualMethodsSize; // 虚方法个数
	/*
	在读取的时候要注意这里的数据是 LEB128 类型。它是一种可变长度类型，每个 LEB128 由 1~5 个字节组成，每个字节只有 7 个有效位。
	如果第一个字节的最高位为 1，表示需要继续使用第 2 个字节，如果第二个字节最高位为 1，表示需要继续使用第三个字节，
	依此类推，直到最后一个字节的最高位为 0，至多 5 个字节。除了 LEB128 以外，还有无符号类型 ULEB128。
	*/
};

/* 类的数据描述，大小占32字节*/
struct DexClassData {
	DexClassDataHeader header;
	DexField*		staticFields; // 静态字段 
	DexField*		instanceFields; // 实例字段
	DexMethod*	directMethods; // 直接方法
	DexMethod*	virtualMethods; // 虚方法
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

