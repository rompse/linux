#ifndef __KVM_X86_INTROSPECTION_WINTYPES_H
#define __KVM_X86_INTROSPECTION_WINTYPES_H

typedef void VOID;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint8_t UCHAR;
typedef uint16_t USHORT;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;
typedef uint16_t WCHAR;

struct _UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x8
};

union _LARGE_INTEGER
{
	struct
	{
		ULONG LowPart;                                                      //0x0
		LONG HighPart;                                                      //0x4
	};
	struct
	{
		ULONG LowPart;                                                      //0x0
		LONG HighPart;                                                      //0x4
	} u;                                                                    //0x0
	LONGLONG QuadPart;                                                      //0x0
};

struct _LIST_ENTRY
{
	struct _LIST_ENTRY* Flink;                                              //0x0
	struct _LIST_ENTRY* Blink;                                              //0x8
};

struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red:1;                                                    //0x10
			UCHAR Balance:2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
};

enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonEnclavePrimary = 7,
	LoadReasonEnclaveDependency = 8,
	LoadReasonPatchImage = 9,
	LoadReasonUnknown = -1
};

enum _LDR_HOT_PATCH_STATE
{
	LdrHotPatchBaseImage = 0,
	LdrHotPatchNotApplied = 1,
	LdrHotPatchAppliedReverse = 2,
	LdrHotPatchAppliedForward = 3,
	LdrHotPatchFailedToPatch = 4,
	LdrHotPatchStateMax = 5
};

struct _LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	ULONGLONG DllBase;                                                      //0x30
	ULONGLONG EntryPoint;                                                   //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary:1;                                         //0x68
			ULONG MarkedForRemoval:1;                                       //0x68
			ULONG ImageDll:1;                                               //0x68
			ULONG LoadNotificationsSent:1;                                  //0x68
			ULONG TelemetryEntryProcessed:1;                                //0x68
			ULONG ProcessStaticImport:1;                                    //0x68
			ULONG InLegacyLists:1;                                          //0x68
			ULONG InIndexes:1;                                              //0x68
			ULONG ShimDll:1;                                                //0x68
			ULONG InExceptionTable:1;                                       //0x68
			ULONG ReservedFlags1:2;                                         //0x68
			ULONG LoadInProgress:1;                                         //0x68
			ULONG LoadConfigProcessed:1;                                    //0x68
			ULONG EntryProcessed:1;                                         //0x68
			ULONG ProtectDelayLoad:1;                                       //0x68
			ULONG ReservedFlags3:2;                                         //0x68
			ULONG DontCallForThreads:1;                                     //0x68
			ULONG ProcessAttachCalled:1;                                    //0x68
			ULONG ProcessAttachFailed:1;                                    //0x68
			ULONG CorDeferredValidate:1;                                    //0x68
			ULONG CorImage:1;                                               //0x68
			ULONG DontRelocate:1;                                           //0x68
			ULONG CorILOnly:1;                                              //0x68
			ULONG ChpeImage:1;                                              //0x68
			ULONG ChpeEmulatorImage:1;                                      //0x68
			ULONG ReservedFlags5:1;                                         //0x68
			ULONG Redirected:1;                                             //0x68
			ULONG ReservedFlags6:2;                                         //0x68
			ULONG CompatDatabaseProcessed:1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
	ULONG CheckSum;                                                         //0x120
	VOID* ActivePatchImageBase;                                             //0x128
	enum _LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
};

struct _IMAGE_DOS_HEADER
{
	USHORT e_magic;                                                         //0x0
	USHORT e_cblp;                                                          //0x2
	USHORT e_cp;                                                            //0x4
	USHORT e_crlc;                                                          //0x6
	USHORT e_cparhdr;                                                       //0x8
	USHORT e_minalloc;                                                      //0xa
	USHORT e_maxalloc;                                                      //0xc
	USHORT e_ss;                                                            //0xe
	USHORT e_sp;                                                            //0x10
	USHORT e_csum;                                                          //0x12
	USHORT e_ip;                                                            //0x14
	USHORT e_cs;                                                            //0x16
	USHORT e_lfarlc;                                                        //0x18
	USHORT e_ovno;                                                          //0x1a
	USHORT e_res[4];                                                        //0x1c
	USHORT e_oemid;                                                         //0x24
	USHORT e_oeminfo;                                                       //0x26
	USHORT e_res2[10];                                                      //0x28
	LONG e_lfanew;                                                          //0x3c
};

struct _IMAGE_FILE_HEADER
{
	USHORT Machine;                                                         //0x0
	USHORT NumberOfSections;                                                //0x2
	ULONG TimeDateStamp;                                                    //0x4
	ULONG PointerToSymbolTable;                                             //0x8
	ULONG NumberOfSymbols;                                                  //0xc
	USHORT SizeOfOptionalHeader;                                            //0x10
	USHORT Characteristics;                                                 //0x12
};

struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;                                                   //0x0
	ULONG Size;                                                             //0x4
};

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
struct _IMAGE_EXPORT_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	USHORT  MajorVersion;
	USHORT  MinorVersion;
	ULONG   Name;
	ULONG   Base;
	ULONG   NumberOfFunctions;
	ULONG   NumberOfNames;
	ULONG   AddressOfFunctions;
	ULONG   AddressOfNames;
	ULONG   AddressOfNameOrdinals;
};

struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;                                                           //0x0
	UCHAR MajorLinkerVersion;                                               //0x2
	UCHAR MinorLinkerVersion;                                               //0x3
	ULONG SizeOfCode;                                                       //0x4
	ULONG SizeOfInitializedData;                                            //0x8
	ULONG SizeOfUninitializedData;                                          //0xc
	ULONG AddressOfEntryPoint;                                              //0x10
	ULONG BaseOfCode;                                                       //0x14
	ULONGLONG ImageBase;                                                    //0x18
	ULONG SectionAlignment;                                                 //0x20
	ULONG FileAlignment;                                                    //0x24
	USHORT MajorOperatingSystemVersion;                                     //0x28
	USHORT MinorOperatingSystemVersion;                                     //0x2a
	USHORT MajorImageVersion;                                               //0x2c
	USHORT MinorImageVersion;                                               //0x2e
	USHORT MajorSubsystemVersion;                                           //0x30
	USHORT MinorSubsystemVersion;                                           //0x32
	ULONG Win32VersionValue;                                                //0x34
	ULONG SizeOfImage;                                                      //0x38
	ULONG SizeOfHeaders;                                                    //0x3c
	ULONG CheckSum;                                                         //0x40
	USHORT Subsystem;                                                       //0x44
	USHORT DllCharacteristics;                                              //0x46
	ULONGLONG SizeOfStackReserve;                                           //0x48
	ULONGLONG SizeOfStackCommit;                                            //0x50
	ULONGLONG SizeOfHeapReserve;                                            //0x58
	ULONGLONG SizeOfHeapCommit;                                             //0x60
	ULONG LoaderFlags;                                                      //0x68
	ULONG NumberOfRvaAndSizes;                                              //0x6c
	struct _IMAGE_DATA_DIRECTORY DataDirectory[16];                         //0x70
};

struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;                                                        //0x0
	struct _IMAGE_FILE_HEADER FileHeader;                                   //0x4
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;                         //0x18
};

#endif //__KVM_X86_INTROSPECTION_WINTYPES_H
