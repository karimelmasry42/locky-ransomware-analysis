typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef struct PMD PMD, *PPMD;

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef int ptrdiff_t;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    RTTIClassHierarchyDescriptor *pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor **pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    RTTIClassHierarchyDescriptor *pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef uint uintptr_t;

typedef struct lconv lconv, *Plconv;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef uint size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef size_t rsize_t;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef uchar BYTE;

typedef union _union_226 _union_226, *P_union_226;

typedef ulong DWORD;

typedef ushort WORD;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef int BOOL;

typedef BYTE *PBYTE;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_34 IMAGE_RESOURCE_DIR_STRING_U_34, *PIMAGE_RESOURCE_DIR_STRING_U_34;

struct IMAGE_RESOURCE_DIR_STRING_U_34 {
    word Length;
    wchar16 NameString[17];
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
    pointer32 GuardCFCCheckFunctionPointer;
    pointer32 GuardCFDispatchFunctionPointer;
    pointer32 GuardCFFunctionTable;
    dword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
};

typedef enum __acrt_lock_id {
} __acrt_lock_id;

typedef struct __crt_signal_action_t __crt_signal_action_t, *P__crt_signal_action_t;

struct __crt_signal_action_t { // PlaceHolder Structure
};

typedef struct <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>, *P<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>;

struct <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> { // PlaceHolder Structure
};

typedef struct <lambda_978dc153c237d78434369da87b74ff60> <lambda_978dc153c237d78434369da87b74ff60>, *P<lambda_978dc153c237d78434369da87b74ff60>;

struct <lambda_978dc153c237d78434369da87b74ff60> { // PlaceHolder Structure
};

typedef struct __crt_locale_data __crt_locale_data, *P__crt_locale_data;

struct __crt_locale_data { // PlaceHolder Structure
};

typedef struct <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c>, *P<lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c>;

struct <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> { // PlaceHolder Structure
};

typedef struct <lambda_e69574bed617af4e071282c136b37893> <lambda_e69574bed617af4e071282c136b37893>, *P<lambda_e69574bed617af4e071282c136b37893>;

struct <lambda_e69574bed617af4e071282c136b37893> { // PlaceHolder Structure
};

typedef struct <lambda_4a8533e2866a575feecb8298ce776b0d> <lambda_4a8533e2866a575feecb8298ce776b0d>, *P<lambda_4a8533e2866a575feecb8298ce776b0d>;

struct <lambda_4a8533e2866a575feecb8298ce776b0d> { // PlaceHolder Structure
};

typedef struct <lambda_be2b3da3f62db62e9dad5dc70221a656> <lambda_be2b3da3f62db62e9dad5dc70221a656>, *P<lambda_be2b3da3f62db62e9dad5dc70221a656>;

struct <lambda_be2b3da3f62db62e9dad5dc70221a656> { // PlaceHolder Structure
};

typedef struct <lambda_293819299cbf9a7022e18b56a874bb5c> <lambda_293819299cbf9a7022e18b56a874bb5c>, *P<lambda_293819299cbf9a7022e18b56a874bb5c>;

struct <lambda_293819299cbf9a7022e18b56a874bb5c> { // PlaceHolder Structure
};

typedef enum _crt_exit_cleanup_mode {
} _crt_exit_cleanup_mode;

typedef struct <lambda_6dbb1268764f43b569ce7b67e331d33a> <lambda_6dbb1268764f43b569ce7b67e331d33a>, *P<lambda_6dbb1268764f43b569ce7b67e331d33a>;

struct <lambda_6dbb1268764f43b569ce7b67e331d33a> { // PlaceHolder Structure
};

typedef struct __crt_seh_guarded_call<void> __crt_seh_guarded_call<void>, *P__crt_seh_guarded_call<void>;

struct __crt_seh_guarded_call<void> { // PlaceHolder Structure
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ { // PlaceHolder Structure
};

typedef enum _crt_argv_mode {
} _crt_argv_mode;

typedef struct <lambda_995298e7d72eb4c2aab26c0585b3abe5> <lambda_995298e7d72eb4c2aab26c0585b3abe5>, *P<lambda_995298e7d72eb4c2aab26c0585b3abe5>;

struct <lambda_995298e7d72eb4c2aab26c0585b3abe5> { // PlaceHolder Structure
};

typedef struct __crt_stdio_stream __crt_stdio_stream, *P__crt_stdio_stream;

struct __crt_stdio_stream { // PlaceHolder Structure
};

typedef struct <lambda_6978c1fb23f02e42e1d9e99668cc68aa> <lambda_6978c1fb23f02e42e1d9e99668cc68aa>, *P<lambda_6978c1fb23f02e42e1d9e99668cc68aa>;

struct <lambda_6978c1fb23f02e42e1d9e99668cc68aa> { // PlaceHolder Structure
};

typedef struct __crt_multibyte_data __crt_multibyte_data, *P__crt_multibyte_data;

struct __crt_multibyte_data { // PlaceHolder Structure
};

typedef struct __crt_seh_guarded_call<int> __crt_seh_guarded_call<int>, *P__crt_seh_guarded_call<int>;

struct __crt_seh_guarded_call<int> { // PlaceHolder Structure
};

typedef struct <lambda_800076c951b434888f4765a74a194fcc> <lambda_800076c951b434888f4765a74a194fcc>, *P<lambda_800076c951b434888f4765a74a194fcc>;

struct <lambda_800076c951b434888f4765a74a194fcc> { // PlaceHolder Structure
};

typedef struct <lambda_6250bd4b2a391816dd638c3bf72b0bcb> <lambda_6250bd4b2a391816dd638c3bf72b0bcb>, *P<lambda_6250bd4b2a391816dd638c3bf72b0bcb>;

struct <lambda_6250bd4b2a391816dd638c3bf72b0bcb> { // PlaceHolder Structure
};

typedef struct __acrt_ptd __acrt_ptd, *P__acrt_ptd;

struct __acrt_ptd { // PlaceHolder Structure
};

typedef struct <lambda_275893d493268fdec8709772e3fcec0e> <lambda_275893d493268fdec8709772e3fcec0e>, *P<lambda_275893d493268fdec8709772e3fcec0e>;

struct <lambda_275893d493268fdec8709772e3fcec0e> { // PlaceHolder Structure
};

typedef struct <lambda_4e60a939b0d047cfe11ddc22648dfba9> <lambda_4e60a939b0d047cfe11ddc22648dfba9>, *P<lambda_4e60a939b0d047cfe11ddc22648dfba9>;

struct <lambda_4e60a939b0d047cfe11ddc22648dfba9> { // PlaceHolder Structure
};

typedef enum _crt_exit_return_mode {
} _crt_exit_return_mode;

typedef struct __crt_locale_pointers __crt_locale_pointers, *P__crt_locale_pointers;

struct __crt_locale_pointers { // PlaceHolder Structure
};

typedef struct <lambda_ec61778202f4f5fc7e7711acc23c3bca> <lambda_ec61778202f4f5fc7e7711acc23c3bca>, *P<lambda_ec61778202f4f5fc7e7711acc23c3bca>;

struct <lambda_ec61778202f4f5fc7e7711acc23c3bca> { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct <lambda_b2ea41f6bbb362cd97d94c6828d90b61> <lambda_b2ea41f6bbb362cd97d94c6828d90b61>, *P<lambda_b2ea41f6bbb362cd97d94c6828d90b61>;

struct <lambda_b2ea41f6bbb362cd97d94c6828d90b61> { // PlaceHolder Structure
};

typedef enum module_id {
} module_id;

typedef enum function_id {
} function_id;

typedef struct dual_state_global<void_(__cdecl*)(int)> dual_state_global<void_(__cdecl*)(int)>, *Pdual_state_global<void_(__cdecl*)(int)>;

struct dual_state_global<void_(__cdecl*)(int)> { // PlaceHolder Structure
};

typedef struct write_result write_result, *Pwrite_result;

struct write_result { // PlaceHolder Structure
};

typedef struct argument_list<char> argument_list<char>, *Pargument_list<char>;

struct argument_list<char> { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);




uint __cdecl FUN_00401000(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  uint uVar1;
  
  if (param_2 == 0) {
    param_2 = param_1 + 0x20;
  }
  *(undefined4 *)(param_1 + 0x30) = param_3;
  *(undefined4 *)(param_1 + 0x34) = param_4;
  uVar1 = ___vcrt_EventRegister(param_2,FUN_00401123,param_1,param_1 + 0x18);
  if (uVar1 == 0) {
    FUN_0040105d(param_1,2,*(ushort **)(param_1 + 4),(uint)**(ushort **)(param_1 + 4));
  }
  else if (0 < (int)uVar1) {
    uVar1 = uVar1 & 0xffff | 0x80070000;
  }
  return uVar1;
}



uint __cdecl FUN_0040105d(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  uint uVar1;
  
  uVar1 = ___vcrt_EventSetInformation
                    (*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x1c),param_2,param_3
                     ,param_4);
  if (0 < (int)uVar1) {
    uVar1 = uVar1 & 0xffff | 0x80070000;
  }
  return uVar1;
}



void __cdecl FUN_00401088(int param_1)

{
  ___vcrt_EventUnregister(*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x1c));
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  return;
}



void __cdecl FUN_004010a7(undefined4 *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
  iVar2 = 0;
  pcVar3 = "";
  if (param_2 != (char *)0x0) {
    pcVar3 = param_2;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    iVar2 = (int)pcVar3 - (int)(param_2 + 1);
    pcVar3 = param_2;
  }
  param_1[1] = 0;
  param_1[3] = 0;
  *param_1 = pcVar3;
  param_1[2] = iVar2 + 1;
  return;
}



void __cdecl FUN_004010df(undefined4 *param_1,short *param_2)

{
  short sVar1;
  int iVar2;
  short *psVar3;
  
  iVar2 = 0;
  psVar3 = (short *)&DAT_00414308;
  if (param_2 != (short *)0x0) {
    psVar3 = param_2;
    do {
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    iVar2 = (int)psVar3 - (int)(param_2 + 1) >> 1;
    psVar3 = param_2;
  }
  param_1[1] = 0;
  param_1[3] = 0;
  *param_1 = psVar3;
  param_1[2] = iVar2 * 2 + 2;
  return;
}



void FUN_00401123(undefined4 param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,
                 int param_7,undefined4 param_8,int *param_9)

{
  code *pcVar1;
  int iVar2;
  
  if (param_9 != (int *)0x0) {
    if (param_2 == 0) {
      *param_9 = 0;
    }
    else if (param_2 == 1) {
      if ((char)param_3 == '\0') {
        iVar2 = 0x100;
      }
      else {
        iVar2 = (param_3 & 0xff) + 1;
      }
      *param_9 = iVar2;
      param_9[2] = param_4;
      param_9[3] = param_5;
      param_9[4] = param_6;
      param_9[5] = param_7;
    }
    pcVar1 = (code *)param_9[0xc];
    if (pcVar1 != (code *)0x0) {
      iVar2 = param_9[0xd];
      guard_check_icall();
      (*pcVar1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2);
    }
  }
  return;
}



uint __cdecl FUN_0040119b(int param_1,uint param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_2 | param_3;
  if (uVar1 != 0) {
    uVar1 = *(uint *)(param_1 + 0xc) & param_3;
    if ((*(uint *)(param_1 + 8) & param_2) != 0 || uVar1 != 0) {
      uVar1 = *(uint *)(param_1 + 0x10) & param_2;
      if ((uVar1 == *(uint *)(param_1 + 0x10)) &&
         ((*(uint *)(param_1 + 0x14) & param_3) == *(uint *)(param_1 + 0x14))) goto LAB_004011d3;
    }
    return uVar1 & 0xffffff00;
  }
LAB_004011d3:
  return CONCAT31((int3)(uVar1 >> 8),1);
}



void __cdecl
FUN_004011d7(int param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 *param_6)

{
  ushort uVar1;
  undefined4 uVar2;
  uint local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_14 = (uint)(param_2 + -0x106362) | 0xb000000;
  local_10 = *param_2;
  local_c = param_2[1];
  local_8 = param_2[2];
  uVar2 = *(undefined4 *)(param_1 + 4);
  param_6[1] = 0;
  *param_6 = uVar2;
  uVar1 = **(ushort **)(param_1 + 4);
  param_6[5] = 0;
  param_6[2] = (uint)uVar1;
  param_6[3] = 2;
  param_6[4] = param_2 + 3;
  param_6[6] = (uint)*(ushort *)(param_2 + 3);
  param_6[7] = 1;
  ___vcrt_EventWriteTransfer
            (*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x1c),&local_14,param_3,
             param_4,param_5,param_6);
  return;
}



void FUN_00401260(void)

{
  FUN_00401400(&DAT_0041aa1f);
  return;
}



void FUN_00401270(void)

{
  FUN_00401400(&DAT_0041aa1a);
  return;
}



void FUN_00401280(void)

{
  FUN_00401400(&DAT_0041aa1d);
  return;
}



void FUN_00401290(void)

{
  FUN_00401400(&DAT_0041aa1b);
  return;
}



void FUN_004012a0(void)

{
  FUN_00401400(&DAT_0041aa24);
  return;
}



void FUN_004012b0(void)

{
  FUN_00401400(&DAT_0041aa22);
  return;
}



void FUN_004012c0(void)

{
  FUN_00401400(&DAT_0041aa21);
  return;
}



void FUN_004012d0(void)

{
  FUN_00401400(&DAT_0041aa1c);
  return;
}



void FUN_004012e0(void)

{
  FUN_00401400(&DAT_0041aa25);
  return;
}



void FUN_004012f0(void)

{
  return;
}



void FUN_00401300(void)

{
  FUN_00401410(&DAT_0041aa26);
  return;
}



void FUN_00401320(void)

{
  return;
}



void FUN_00401330(void)

{
  return;
}



void FUN_00401340(void)

{
  return;
}



void FUN_00401350(void)

{
  return;
}



undefined4 FUN_00401360(void)

{
  FUN_00407330(0x28);
  FUN_004050a0();
  return 0;
}



undefined4 FUN_004013f0(undefined4 param_1)

{
  return param_1;
}



undefined4 __fastcall FUN_00401400(undefined4 param_1)

{
  return param_1;
}



undefined4 __fastcall FUN_00401410(undefined4 param_1)

{
  return param_1;
}



undefined4 FUN_00401420(undefined4 param_1)

{
  undefined4 uVar1;
  undefined1 local_c [4];
  int local_8;
  
  local_8 = (*DAT_0041ab78)(param_1,0x80000000,0,0,3,0,0);
  if (local_8 == -1) {
    uVar1 = 0;
  }
  else {
    DAT_0041aa30 = (*DAT_0041ab94)(local_8,0);
    if (DAT_0041aa30 == -1) {
      uVar1 = 0;
    }
    else {
      DAT_0041aa34 = (short *)(*DAT_0041ab84)(0x40,DAT_0041aa30);
      if (DAT_0041aa34 == (short *)0x0) {
        uVar1 = 0;
      }
      else {
        uVar1 = (*DAT_0041ab94)(local_8,0,local_c,0);
        (*DAT_0041ab7c)(local_8,DAT_0041aa34,uVar1);
        (*DAT_0041ab80)(local_8);
        DAT_0041ab3c = DAT_0041aa34;
        if (*DAT_0041aa34 == 0x5a4d) {
          DAT_0041ab40 = (int *)((int)DAT_0041aa34 + *(int *)(DAT_0041aa34 + 0x1e));
          if (*DAT_0041ab40 == 0x4550) {
            uVar1 = 1;
          }
          else {
            uVar1 = 0;
          }
        }
        else {
          uVar1 = (*DAT_0041ab8c)(8,DAT_0041aa34);
          (*DAT_0041ab88)(uVar1);
          uVar1 = 0;
        }
      }
    }
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401a10(void)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  uint uVar6;
  int *local_8;
  
  uVar6 = 0xb;
  puVar5 = &DAT_0041a010;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xb;
  puVar5 = &DAT_0041a034;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xb;
  puVar5 = &DAT_0041a028;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 8;
  puVar5 = &DAT_0041a01c;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xb;
  puVar5 = &DAT_0041a04c;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 8;
  puVar5 = &DAT_0041a040;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xe;
  puVar5 = &DAT_0041a058;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xb;
  puVar5 = &DAT_0041a068;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x12;
  puVar5 = &DAT_0041a074;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x13;
  puVar5 = &DAT_0041a088;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xe;
  puVar5 = &DAT_0041a0e8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 10;
  puVar5 = &DAT_0041a09c;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 6;
  puVar5 = &DAT_0041a0c0;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xc;
  puVar5 = &DAT_0041a0c8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 5;
  puVar5 = &DAT_0041a0b8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 9;
  puVar5 = &DAT_0041a1d8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x14;
  puVar5 = &DAT_0041a100;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xb;
  puVar5 = &DAT_0041a118;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xe;
  puVar5 = &DAT_0041a124;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xc;
  puVar5 = &DAT_0041a134;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x10;
  puVar5 = &DAT_0041a144;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x11;
  puVar5 = &DAT_0041a1b0;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x12;
  puVar5 = &DAT_0041a168;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xe;
  puVar5 = &DAT_0041a158;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xc;
  puVar5 = &DAT_0041a190;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xd;
  puVar5 = &DAT_0041a1a0;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x10;
  puVar5 = &DAT_0041a17c;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0x10;
  puVar5 = &DAT_0041a1c4;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  piVar1 = *(int **)(*(int *)((int)ProcessEnvironmentBlock + 0xc) + 0x1c);
  local_8 = piVar1;
  do {
    iVar4 = local_8[2];
    iVar3 = FUN_00403950(iVar4,0x41a0d8);
    if (iVar3 != 0) {
      DAT_0041ab70 = (code *)FUN_00403950(iVar4,0x41a0d8);
      break;
    }
    local_8 = (int *)*local_8;
  } while (piVar1 != local_8);
  puVar5 = &DAT_0041a09c;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a09c,&DAT_0041a010);
  _DAT_0041ab74 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a034);
  DAT_0041ab78 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a01c);
  DAT_0041ab7c = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a028);
  DAT_0041ab80 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a04c);
  DAT_0041ab84 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a058);
  DAT_0041ab8c = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a040);
  DAT_0041ab88 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a040);
  DAT_0041ab88 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a068);
  DAT_0041ab94 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a074);
  DAT_0041ab98 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a088);
  DAT_0041aba4 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a1c4);
  DAT_0041aba0 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a1d8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a1d8,&DAT_0041a100);
  DAT_0041abb0 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a118);
  DAT_0041abb4 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a124);
  DAT_0041abb8 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a134);
  DAT_0041abbc = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a144);
  DAT_0041abc0 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a1b0);
  DAT_0041abc4 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a158);
  DAT_0041abc8 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a168);
  DAT_0041abcc = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a17c);
  DAT_0041abd0 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a190);
  DAT_0041abd4 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a1a0);
  _DAT_0041abd8 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a0c0);
  DAT_0041abac = FUN_00403950(iVar4,(int)puVar5);
  return;
}



int FUN_00403950(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint local_c;
  
  iVar5 = param_1 + *(int *)(param_1 + *(int *)(param_1 + 0x3c) + 0x78);
  iVar1 = *(int *)(iVar5 + 0x20);
  iVar2 = *(int *)(iVar5 + 0x1c);
  iVar3 = *(int *)(iVar5 + 0x24);
  uVar4 = *(uint *)(iVar5 + 0x18);
  local_c = 0;
  while( true ) {
    if (uVar4 <= local_c) {
      return 0;
    }
    iVar5 = FUN_00403f10(param_2,param_1 + *(int *)(param_1 + iVar1 + local_c * 4),1000);
    if (iVar5 == 0) break;
    local_c = local_c + 1;
  }
  return param_1 + *(int *)(param_1 + iVar2 + (uint)*(ushort *)(param_1 + iVar3 + local_c * 2) * 4);
}



undefined4 FUN_00403f10(int param_1,int param_2,int param_3)

{
  int local_8;
  
  local_8 = 0;
  while( true ) {
    if (param_3 <= local_8) {
      return 0;
    }
    if (*(char *)(param_1 + local_8) != *(char *)(param_2 + local_8)) break;
    if ((*(char *)(param_1 + local_8) == '\0') && (*(char *)(param_2 + local_8) == '\0')) {
      return 0;
    }
    local_8 = local_8 + 1;
  }
  return 1;
}



undefined8 FUN_00404100(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint auStack_48 [10];
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_14 = 0;
  local_8 = 0;
  local_c = 0;
  local_20 = (*DAT_0041ab84)(0x40,0x24);
  local_1c = (*DAT_0041ab84)(0x40,0x24);
  for (; local_c < DAT_0041aa30; local_c = local_c + 1) {
    local_18 = param_1 + local_c;
    iVar1 = FUN_00403f10(local_18,0x41a1e4,DAT_0041a1f0);
    if (iVar1 == 0) {
      auStack_48[local_14] = local_c;
      local_14 = local_14 + 1;
    }
  }
  for (; local_8 < local_14 - 1U; local_8 = local_8 + 1) {
    uVar2 = (*DAT_0041ab84)(0x40,(auStack_48[local_8 + 1] - auStack_48[local_8]) - DAT_0041a1f0);
    *(undefined4 *)(local_20 + local_8 * 4) = uVar2;
    for (local_10 = 0; local_10 < (auStack_48[local_8 + 1] - auStack_48[local_8]) - DAT_0041a1f0;
        local_10 = local_10 + 1) {
      *(undefined1 *)(*(int *)(local_20 + local_8 * 4) + local_10) =
           *(undefined1 *)(param_1 + local_10 + auStack_48[local_8] + DAT_0041a1f0);
    }
    *(uint *)(local_1c + local_8 * 4) =
         (auStack_48[local_8 + 1] - auStack_48[local_8]) - DAT_0041a1f0;
  }
  return CONCAT44(local_1c,local_20);
}



// WARNING: Removing unreachable block (ram,0x00404f17)

int FUN_00404770(int param_1,int param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint auStack_418 [256];
  uint local_18;
  byte local_11;
  uint local_10;
  uint local_c;
  byte local_5;
  
  local_10 = 0;
  for (local_c = 0; (int)local_c < 0x100; local_c = local_c + 1) {
    auStack_418[local_c] = local_c;
  }
  for (local_c = 0; (int)local_c < 0x100; local_c = local_c + 1) {
    local_10 = local_10 + auStack_418[local_c] + (uint)*(byte *)(param_2 + local_c % param_4) &
               0x800000ff;
    if ((int)local_10 < 0) {
      local_10 = (local_10 - 1 | 0xffffff00) + 1;
    }
    uVar1 = auStack_418[local_c];
    local_5 = (byte)uVar1;
    auStack_418[local_c] = auStack_418[local_10];
    auStack_418[local_10] = (uint)(byte)uVar1;
  }
  local_10 = 0;
  local_c = 0;
  for (local_18 = 0; local_18 < param_3; local_18 = local_18 + 1) {
    local_c = local_c + 1 & 0x800000ff;
    if ((int)local_c < 0) {
      local_c = (local_c - 1 | 0xffffff00) + 1;
    }
    local_10 = local_10 + auStack_418[local_c] & 0x800000ff;
    if ((int)local_10 < 0) {
      local_10 = (local_10 - 1 | 0xffffff00) + 1;
    }
    local_5 = (byte)auStack_418[local_c];
    auStack_418[local_c] = auStack_418[local_10];
    auStack_418[local_10] = (uint)local_5;
    local_11 = (char)auStack_418[local_c] + (char)auStack_418[local_10];
    local_5 = (byte)auStack_418[local_11];
    *(byte *)(param_1 + local_18) = *(byte *)(param_1 + local_18) ^ (byte)auStack_418[local_11];
  }
  return param_1;
}



undefined4 FUN_00405030(void)

{
  return DAT_0041aa34;
}



void FUN_004050a0(void)

{
  FUN_00407150(0x1e);
  FUN_00407330(0x1e);
  FUN_00407580();
  FUN_00407280();
  FUN_00406750();
  FUN_00407330(0x2a);
  FUN_00406ea0(5000);
  FUN_00405ce0();
  return;
}



undefined4 FUN_00405380(void)

{
  return DAT_0041aa30;
}



undefined * FUN_004053f0(void)

{
  (*DAT_0041ab98)(0,&DAT_0041aa38,0x104);
  return &DAT_0041aa38;
}



undefined4 FUN_00405550(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  undefined4 local_8;
  
  (*DAT_0041ab98)(0,&DAT_0041aa38,0x104);
  iVar1 = (*DAT_0041aba4)(0xfde9,0,&DAT_0041aa38,0xffffffff,0,0);
  uVar2 = (*DAT_0041abac)(0,&DAT_0041aa38,0xffffffff,0,0);
  iVar3 = (*DAT_0041aba4)(uVar2);
  if (iVar1 == iVar3) {
    local_8 = 0xfde9;
  }
  else {
    local_8 = (*DAT_0041abac)();
  }
  uVar4 = (*DAT_0041aba4)(local_8,0,&DAT_0041aa38,0xffffffff,0,0);
  uVar2 = FUN_004096b3(-(uint)((int)((ulonglong)uVar4 * 2 >> 0x20) != 0) |
                       (uint)((ulonglong)uVar4 * 2));
  (*DAT_0041aba4)(local_8,0,&DAT_0041aa38,0xffffffff,uVar2,uVar4);
  return uVar2;
}



void FUN_00405900(int param_1,int param_2)

{
  byte *pbVar1;
  uint uVar2;
  int local_10;
  int local_8;
  
  pbVar1 = (byte *)(*DAT_0041ab84)(0x40,5);
  local_10 = 0;
  for (local_8 = 0; local_8 < param_2 + -2; local_8 = local_8 + 2) {
    pbVar1[4] = 0;
    pbVar1[3] = *(byte *)(param_1 + local_8 + 1);
    pbVar1[2] = *(byte *)(param_1 + local_8);
    *pbVar1 = 0x30;
    pbVar1[1] = 0x78;
    uVar2 = FUN_004069d0(pbVar1);
    *(char *)(param_1 + local_10) = (char)uVar2;
    local_10 = local_10 + 1;
  }
  return;
}



undefined4 FUN_00405ce0(void)

{
  undefined *puVar1;
  int iVar2;
  undefined8 uVar3;
  short *psVar4;
  undefined4 local_1c;
  undefined4 local_18;
  
  FUN_00401a10();
  puVar1 = FUN_004053f0();
  FUN_00401420(puVar1);
  FUN_00405380();
  iVar2 = FUN_00405030();
  uVar3 = FUN_00404100(iVar2);
  local_1c = (int)uVar3;
  local_18 = (int)((ulonglong)uVar3 >> 0x20);
  *(undefined1 *)(*(int *)(local_1c + 0x10) + *(int *)(local_18 + 0x10)) = 0;
  iVar2 = FUN_00404770(*(int *)(local_1c + 4),*(int *)(local_1c + 0x10),*(uint *)(local_18 + 4),
                       *(uint *)(local_18 + 0x10));
  *(int *)(local_1c + 4) = iVar2;
  iVar2 = FUN_00404770(*(int *)(local_1c + 0x1c),*(int *)(local_1c + 0x10),
                       *(uint *)(local_18 + 0x1c),*(uint *)(local_18 + 0x10));
  *(int *)(local_1c + 0x1c) = iVar2;
  iVar2 = FUN_00404770(*(int *)(local_1c + 0x20),*(int *)(local_1c + 0x10),
                       *(uint *)(local_18 + 0x20),*(uint *)(local_18 + 0x10));
  *(int *)(local_1c + 0x20) = iVar2;
  FUN_00405900(*(int *)(local_1c + 0x1c),*(int *)(local_18 + 0x1c));
  FUN_00405900(*(int *)(local_1c + 0x20),*(int *)(local_18 + 0x20));
  psVar4 = *(short **)(local_1c + 4);
  puVar1 = FUN_004053f0();
  FUN_00408a20(puVar1,psVar4);
  return 0;
}



undefined4 FUN_00406750(void)

{
  FUN_00407330(0x1d);
  DAT_0041a008 = 0x32;
  DAT_0041a00c = 0;
  return 0;
}



uint FUN_004069d0(byte *param_1)

{
  bool bVar1;
  bool bVar2;
  uint local_10;
  uint local_c;
  
  local_10 = 0;
  local_c = 0;
  if ((*param_1 == 0x30) && (param_1[1] == 0x78)) {
    for (param_1 = param_1 + 2; *param_1 != 0; param_1 = param_1 + 1) {
      local_10 = local_10 << 4;
      if (((int)local_c < 0) || (5 < (int)local_c)) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      local_c = *param_1 - 0x30;
      if (((int)local_c < 0) || (9 < (int)local_c)) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
      if (bVar1) {
        local_10 = local_10 | local_c;
      }
      else {
        local_c = *param_1 - 0x41;
        if (bVar2) {
          local_10 = *param_1 - 0x37 | local_10;
        }
        else {
          local_c = *param_1 - 0x61;
          if (((int)local_c < 0) || (5 < (int)local_c)) {
            bVar2 = false;
          }
          else {
            bVar2 = true;
          }
          if (!bVar2) {
            return local_10;
          }
          local_10 = *param_1 - 0x57 | local_10;
        }
      }
    }
  }
  return local_10;
}



undefined4 FUN_00406e80(void)

{
  return DAT_0041a008;
}



void FUN_00406ea0(undefined4 param_1)

{
  (*DAT_0041aba8)(param_1);
  return;
}



void FUN_00406f70(undefined4 param_1)

{
  undefined1 local_8 [4];
  
  (*DAT_0041ab9c)(0,0,param_1,0,0,local_8);
  return;
}



int FUN_00407150(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    iVar1 = 1;
  }
  else {
    iVar1 = FUN_00407150(param_1 + -1);
    iVar1 = iVar1 * param_1;
  }
  return iVar1;
}



void FUN_00407280(void)

{
  FUN_00406f70(FUN_00406750);
  FUN_00406f70(FUN_00406750);
  return;
}



int FUN_00407330(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  if (param_1 == 0) {
    iVar1 = 0;
  }
  else if (param_1 == 1) {
    iVar1 = 1;
  }
  else {
    iVar1 = FUN_00407330(0);
    iVar2 = FUN_00407330(param_1 + -1);
    iVar3 = FUN_00407330(1);
    iVar4 = FUN_00407330(0);
    iVar5 = FUN_00407330(1);
    iVar6 = FUN_00407330(param_1 + -2);
    iVar1 = (iVar6 + (iVar3 - (iVar4 + 1)) + 2 + iVar5) - (iVar1 + 1 + iVar2);
  }
  return iVar1;
}



void FUN_00407580(void)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  uint uVar6;
  int *local_8;
  
  uVar6 = 0xc;
  puVar5 = &DAT_0041a0d8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  piVar1 = *(int **)(*(int *)((int)ProcessEnvironmentBlock + 0xc) + 0x1c);
  local_8 = piVar1;
  do {
    iVar4 = local_8[2];
    iVar3 = FUN_00403950(iVar4,0x41a0d8);
    if (iVar3 != 0) {
      DAT_0041ab70 = (code *)FUN_00403950(iVar4,0x41a0d8);
      break;
    }
    local_8 = (int *)*local_8;
  } while (piVar1 != local_8);
  uVar6 = 0xc;
  puVar5 = &DAT_0041a0a8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 0xc;
  puVar5 = &DAT_0041a0c8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  uVar6 = 5;
  puVar5 = &DAT_0041a0b8;
  uVar2 = FUN_00408990(0x41a0f8);
  FUN_00408050(0x41a0f8,uVar2,(int)puVar5,uVar6);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a0b8);
  DAT_0041aba8 = FUN_00403950(iVar4,(int)puVar5);
  puVar5 = &DAT_0041a0a8;
  iVar4 = (*DAT_0041ab70)(&DAT_0041a0a8,&DAT_0041a0c8);
  DAT_0041ab9c = FUN_00403950(iVar4,(int)puVar5);
  return;
}



// WARNING: Removing unreachable block (ram,0x0040871b)

int FUN_00408050(int param_1,uint param_2,int param_3,uint param_4)

{
  byte bVar1;
  byte abStack_120 [256];
  uint local_20;
  int local_1c;
  int local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_18 = param_3;
  local_1c = param_1;
  for (local_8 = 0; (int)local_8 < 0x100; local_8 = local_8 + 1) {
    abStack_120[local_8] = (byte)local_8;
  }
  local_c = 0;
  for (local_8 = 0; (int)local_8 < 0x100; local_8 = local_8 + 1) {
    local_c = abStack_120[local_8] + local_c + (int)*(char *)(local_1c + local_8 % param_2) &
              0x800000ff;
    if ((int)local_c < 0) {
      local_c = (local_c - 1 | 0xffffff00) + 1;
    }
    bVar1 = abStack_120[local_8];
    local_14 = (uint)bVar1;
    abStack_120[local_8] = abStack_120[local_c];
    abStack_120[local_c] = bVar1;
  }
  local_c = 0;
  local_8 = 0;
  for (local_10 = 0; local_10 < param_4; local_10 = local_10 + 1) {
    local_8 = local_8 + 1 & 0x800000ff;
    if ((int)local_8 < 0) {
      local_8 = (local_8 - 1 | 0xffffff00) + 1;
    }
    local_c = abStack_120[local_8] + local_c & 0x800000ff;
    if ((int)local_c < 0) {
      local_c = (local_c - 1 | 0xffffff00) + 1;
    }
    local_14 = (uint)abStack_120[local_8];
    abStack_120[local_8] = abStack_120[local_c];
    abStack_120[local_c] = (byte)local_14;
    local_20 = (uint)abStack_120[local_8] + (uint)abStack_120[local_c];
    local_14 = (uint)abStack_120
                     [(uint)abStack_120[local_8] + (uint)abStack_120[local_c] & 0x800000ff];
    *(byte *)(local_18 + local_10) =
         *(byte *)(local_18 + local_10) ^
         abStack_120[(uint)abStack_120[local_8] + (uint)abStack_120[local_c] & 0x800000ff];
  }
  return local_18;
}



int FUN_00408840(int param_1,int param_2)

{
  return param_1 + param_2 * 2;
}



int FUN_00408850(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 == 0) {
    iVar1 = 1;
  }
  else if (param_1 == 1) {
    iVar1 = 2;
  }
  else {
    iVar2 = FUN_00408850(param_1 + -1);
    iVar1 = FUN_00408850(param_1 + -2);
    iVar1 = iVar1 * iVar2;
  }
  return iVar1;
}



int FUN_00408990(int param_1)

{
  undefined4 local_8;
  
  for (local_8 = 0; *(char *)(param_1 + local_8) != '\0'; local_8 = local_8 + 1) {
  }
  return local_8;
}



void FUN_00408a20(undefined4 param_1,short *param_2)

{
  int iVar1;
  undefined1 local_78 [68];
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_24;
  int local_20;
  int local_1c;
  short *local_18;
  int local_14;
  int local_10;
  undefined4 *local_c;
  int *local_8;
  
  local_18 = param_2;
  if ((*param_2 == 0x5a4d) &&
     (local_8 = (int *)((int)param_2 + *(int *)(param_2 + 0x1e)), *local_8 == 0x4550)) {
    while( true ) {
      FUN_00409680(local_78,0x44);
      FUN_00409680((undefined1 *)&local_34,0x10);
      local_24 = 4;
      iVar1 = (*DAT_0041abb8)(param_1,0,0,0,0,4,0,0,local_78,&local_34);
      if (iVar1 == 0) break;
      local_c = (undefined4 *)(*DAT_0041abbc)(0,4,0x1000,4);
      *local_c = 0x10007;
      iVar1 = (*DAT_0041abc0)(local_30,local_c);
      if (iVar1 == 0) break;
      (*DAT_0041abc4)(local_34,local_c[0x29] + 8,&local_20,4,0);
      if (local_20 == local_8[0xd]) {
        (*DAT_0041abb0)(local_34,local_20);
      }
      local_10 = (*DAT_0041abc8)(local_34,local_8[0xd],local_8[0x14],0x3000,0x40);
      if (local_10 != 0) {
        if (local_10 != 0) {
          (*DAT_0041abcc)(local_34,local_10,param_2,local_8[0x15],0);
          for (local_14 = 0; local_14 < (int)(uint)*(ushort *)((int)local_8 + 6);
              local_14 = local_14 + 1) {
            local_1c = (int)param_2 + local_14 * 0x28 + *(int *)(local_18 + 0x1e) + 0xf8;
            (*DAT_0041abcc)(local_34,local_10 + *(int *)(local_1c + 0xc),
                            (int)param_2 + *(int *)(local_1c + 0x14),
                            *(undefined4 *)(local_1c + 0x10),0);
          }
          (*DAT_0041abcc)(local_34,local_c[0x29] + 8,local_8 + 0xd,4,0);
          local_c[0x2c] = local_10 + local_8[10];
          (*DAT_0041abd0)(local_30,local_c);
          (*DAT_0041abd4)(local_30);
        }
        break;
      }
      (*DAT_0041aba0)(local_34,0);
    }
  }
  (*DAT_0041abb4)(param_2,0,0x8000);
  return;
}



undefined1 * FUN_00409680(undefined1 *param_1,int param_2)

{
  undefined1 *local_8;
  
  local_8 = param_1;
  for (; param_2 != 0; param_2 = param_2 + -1) {
    *local_8 = 0;
    local_8 = local_8 + 1;
  }
  return param_1;
}



void __cdecl FUN_004096b3(uint param_1)

{
  operator_new(param_1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int FUN_0040977a(void)

{
  code *pcVar1;
  bool bVar2;
  bool bVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  uint *puVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  
  uVar4 = ___scrt_initialize_crt(1);
  if ((char)uVar4 != '\0') goto LAB_00409799;
  do {
    ___scrt_fastfail();
LAB_00409799:
    bVar2 = false;
    uVar4 = ___scrt_acquire_startup_lock();
  } while (DAT_0041abe0 == 1);
  if (DAT_0041abe0 == 0) {
    DAT_0041abe0 = 1;
    iVar5 = __initterm_e((undefined4 *)&DAT_00414170,(undefined4 *)&DAT_00414188);
    if (iVar5 != 0) {
      return 0xff;
    }
    __initterm((undefined4 *)&DAT_00414128,(undefined4 *)&DAT_0041416c);
    DAT_0041abe0 = 2;
  }
  else {
    bVar2 = true;
  }
  ___scrt_release_startup_lock((char)uVar4);
  piVar6 = (int *)FUN_00409cc1();
  if ((*piVar6 != 0) && (uVar4 = FUN_00409a93((int)piVar6), (char)uVar4 != '\0')) {
    uVar9 = 0;
    uVar8 = 2;
    uVar4 = 0;
    pcVar1 = (code *)*piVar6;
    guard_check_icall();
    (*pcVar1)(uVar4,uVar8,uVar9);
  }
  puVar7 = (uint *)FUN_00409cc7();
  if ((*puVar7 != 0) && (uVar4 = FUN_00409a93((int)puVar7), (char)uVar4 != '\0')) {
    __register_thread_local_exe_atexit_callback(*puVar7);
  }
  FUN_0040a393(0);
  ___scrt_get_show_window_mode();
  __get_narrow_winmain_command_line();
  iVar5 = FUN_00401360();
  FUN_0040a42f(0);
  bVar3 = is_managed_app();
  if (bVar3) {
    if (!bVar2) {
      __cexit();
    }
    ___scrt_uninitialize_crt('\x01','\0');
    return iVar5;
  }
                    // WARNING: Subroutine does not return
  _exit(iVar5);
}



void entry(void)

{
  ___security_init_cookie();
  FUN_0040977a();
  return;
}



// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2015 Release

void * __cdecl operator_new(uint param_1)

{
  int iVar1;
  void *pvVar2;
  
  while( true ) {
    pvVar2 = (void *)FUN_0040bfdd(param_1);
    if (pvVar2 != (void *)0x0) break;
    iVar1 = __callnewh(param_1);
    if (iVar1 == 0) {
      if (param_1 == 0xffffffff) {
        FID_conflict___scrt_throw_std_bad_alloc();
      }
      else {
        FID_conflict___scrt_throw_std_bad_alloc();
      }
    }
  }
  return pvVar2;
}



// Library Function - Single Match
//  void * __cdecl __crt_fast_encode_pointer<void *>(void * const)
// 
// Library: Visual Studio 2015 Release

void * __cdecl __crt_fast_encode_pointer<void*>(void *param_1)

{
  byte bVar1;
  
  bVar1 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
  return (void *)(((uint)param_1 >> bVar1 | (int)param_1 << 0x20 - bVar1) ^ DAT_0041a208);
}



// Library Function - Single Match
//  struct _IMAGE_SECTION_HEADER * __cdecl find_pe_section(unsigned char * const,unsigned int)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

_IMAGE_SECTION_HEADER * __cdecl find_pe_section(uchar *param_1,uint param_2)

{
  int iVar1;
  _IMAGE_SECTION_HEADER *p_Var2;
  _IMAGE_SECTION_HEADER *p_Var3;
  
  iVar1 = *(int *)(param_1 + 0x3c);
  p_Var2 = (_IMAGE_SECTION_HEADER *)
           (param_1 + (uint)*(ushort *)(param_1 + iVar1 + 0x14) + iVar1 + 0x18);
  p_Var3 = p_Var2 + *(ushort *)(param_1 + iVar1 + 6);
  while( true ) {
    if (p_Var2 == p_Var3) {
      return (_IMAGE_SECTION_HEADER *)0x0;
    }
    if ((p_Var2->VirtualAddress <= param_2) &&
       (param_2 < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) break;
    p_Var2 = p_Var2 + 1;
  }
  return p_Var2;
}



// Library Function - Single Match
//  ___scrt_acquire_startup_lock
// 
// Library: Visual Studio 2015 Release

int ___scrt_acquire_startup_lock(void)

{
  void *pvVar1;
  bool bVar2;
  uint3 extraout_var;
  void *pvVar3;
  uint3 uVar4;
  
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  if (CONCAT31(extraout_var,bVar2) == 0) {
    return (uint)extraout_var << 8;
  }
  while( true ) {
    pvVar3 = (void *)0x0;
    LOCK();
    pvVar1 = StackBase;
    if (DAT_0041abe4 != (void *)0x0) {
      pvVar3 = DAT_0041abe4;
      pvVar1 = DAT_0041abe4;
    }
    DAT_0041abe4 = pvVar1;
    UNLOCK();
    uVar4 = (uint3)((uint)pvVar3 >> 8);
    if (pvVar3 == (void *)0x0) break;
    if (StackBase == pvVar3) {
      return CONCAT31(uVar4,1);
    }
  }
  return (uint)uVar4 << 8;
}



// Library Function - Single Match
//  ___scrt_initialize_crt
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

uint __cdecl ___scrt_initialize_crt(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  
  if (param_1 == 0) {
    DAT_0041ac00 = 1;
  }
  FUN_0040a042();
  uVar1 = FUN_0040a68a();
  if ((char)uVar1 != '\0') {
    uVar2 = ___acrt_initialize();
    if ((char)uVar2 != '\0') {
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
    uVar1 = FUN_0040a6b8('\0');
  }
  return uVar1 & 0xffffff00;
}



// Library Function - Single Match
//  ___scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2015 Release

uint __cdecl ___scrt_initialize_onexit_tables(int param_1)

{
  code *pcVar1;
  byte bVar2;
  bool bVar3;
  undefined3 extraout_var;
  uint uVar4;
  int iVar5;
  
  if ((param_1 != 0) && (param_1 != 1)) {
    ___scrt_fastfail();
    pcVar1 = (code *)swi(3);
    uVar4 = (*pcVar1)();
    return uVar4;
  }
  bVar3 = ___scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar3) == 0) || (param_1 != 0)) {
    bVar2 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
    DAT_0041abe8 = (0xffffffffU >> bVar2 | -1 << 0x20 - bVar2) ^ DAT_0041a208;
    uVar4 = CONCAT31((int3)(DAT_0041abe8 >> 8),1);
    DAT_0041abec = DAT_0041abe8;
    DAT_0041abf0 = DAT_0041abe8;
    DAT_0041abf4 = DAT_0041abe8;
    DAT_0041abf8 = DAT_0041abe8;
    DAT_0041abfc = DAT_0041abe8;
  }
  else {
    uVar4 = __initialize_onexit_table(&DAT_0041abe8);
    if (uVar4 == 0) {
      iVar5 = __initialize_onexit_table(&DAT_0041abf4);
      uVar4 = CONCAT31((int3)((uint)-iVar5 >> 8),'\x01' - (iVar5 != 0));
    }
    else {
      uVar4 = uVar4 & 0xffffff00;
    }
  }
  return uVar4;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

uint __cdecl FUN_00409a93(int param_1)

{
  _IMAGE_SECTION_HEADER *p_Var1;
  uint uVar2;
  
  p_Var1 = find_pe_section((uchar *)&IMAGE_DOS_HEADER_00400000,param_1 - 0x400000);
  if ((p_Var1 == (_IMAGE_SECTION_HEADER *)0x0) || ((p_Var1->Characteristics & 0x80000000) != 0)) {
    uVar2 = (uint)p_Var1 & 0xffffff00;
  }
  else {
    uVar2 = CONCAT31((int3)((uint)p_Var1 >> 8),1);
  }
  return uVar2;
}



// Library Function - Single Match
//  ___scrt_release_startup_lock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl ___scrt_release_startup_lock(char param_1)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  iVar1 = DAT_0041abe4;
  iVar3 = CONCAT31(extraout_var,bVar2);
  if ((iVar3 != 0) && (param_1 == '\0')) {
    LOCK();
    DAT_0041abe4 = 0;
    UNLOCK();
    iVar3 = iVar1;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___scrt_uninitialize_crt
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl ___scrt_uninitialize_crt(char param_1,char param_2)

{
  undefined4 in_EAX;
  
  if ((DAT_0041ac00 == '\0') || (param_2 == '\0')) {
    ___acrt_uninitialize();
    in_EAX = FUN_0040a6b8(param_1);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2015 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  int iVar1;
  byte bVar2;
  
  bVar2 = (byte)DAT_0041a208 & 0x1f;
  if (((DAT_0041a208 ^ DAT_0041abe8) >> bVar2 | (DAT_0041a208 ^ DAT_0041abe8) << 0x20 - bVar2) ==
      0xffffffff) {
    iVar1 = __crt_atexit();
  }
  else {
    iVar1 = __register_onexit_function();
  }
  return (_onexit_t)(~-(uint)(iVar1 != 0) & (uint)_Func);
}



// Library Function - Single Match
//  _atexit
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2015 Release

void __cdecl ___security_init_cookie(void)

{
  uint uVar1;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_10 = 0;
  local_c = 0;
  if ((DAT_0041a208 == 0xbb40e64e) || ((DAT_0041a208 & 0xffff0000) == 0)) {
    (*(code *)0x19832)(&local_10);
    local_8 = local_c ^ local_10;
    uVar1 = (*(code *)0x1981c)();
    local_8 = local_8 ^ uVar1;
    uVar1 = (*(code *)0x19806)();
    local_8 = local_8 ^ uVar1;
    (*(code *)0x197ec)(&local_18);
    DAT_0041a208 = local_14 ^ local_18 ^ local_8 ^ (uint)&local_8;
    if (DAT_0041a208 == 0xbb40e64e) {
      DAT_0041a208 = 0xbb40e64f;
    }
    else if ((DAT_0041a208 & 0xffff0000) == 0) {
      DAT_0041a208 = DAT_0041a208 | (DAT_0041a208 | 0x4711) << 0x10;
    }
    DAT_0041a204 = ~DAT_0041a208;
  }
  else {
    DAT_0041a204 = ~DAT_0041a208;
  }
  return;
}



undefined4 FUN_00409c51(void)

{
  return 1;
}



undefined4 FUN_00409c55(void)

{
  return 0x4000;
}



undefined4 FUN_00409c5b(void)

{
  return 0;
}



void FUN_00409c5e(void)

{
  (*(code *)0x1984c)(&DAT_0041ac08);
  return;
}



// Library Function - Single Match
//  __initialize_default_precision
// 
// Library: Visual Studio 2015 Release

void __initialize_default_precision(void)

{
  code *pcVar1;
  errno_t eVar2;
  
  eVar2 = __controlfp_s((uint *)0x0,0x10000,0x30000);
  if (eVar2 == 0) {
    return;
  }
  ___scrt_fastfail();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// guard_check_icall

void __cdecl guard_check_icall(void)

{
  return;
}



undefined * FUN_00409c8c(void)

{
  return &DAT_0041ac10;
}



undefined * FUN_00409c92(void)

{
  return &DAT_0041ac18;
}



void FUN_00409c98(void)

{
  uint *puVar1;
  
  puVar1 = (uint *)FUN_00409c8c();
  *puVar1 = *puVar1 | 4;
  puVar1[1] = puVar1[1];
  puVar1 = (uint *)FUN_00409c92();
  *puVar1 = *puVar1 | 2;
  puVar1[1] = puVar1[1];
  return;
}



bool FUN_00409cb5(void)

{
  return DAT_0041a1f8 == 0;
}



undefined * FUN_00409cc1(void)

{
  return &DAT_0041b5fc;
}



undefined * FUN_00409cc7(void)

{
  return &DAT_0041b5f8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___scrt_fastfail
// 
// Library: Visual Studio 2015 Release

void ___scrt_fastfail(void)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  undefined4 local_328 [39];
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 *local_c;
  undefined4 *local_8;
  
  iVar2 = FUN_00412d36();
  if (iVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  _DAT_0041ac20 = 0;
  _memset(local_328,0,0x2cc);
  local_328[0] = 0x10001;
  _memset(&local_5c,0,0x50);
  local_5c = 0x40000015;
  local_58 = 1;
  iVar2 = (*(code *)0x19862)();
  local_c = &local_5c;
  local_8 = local_328;
  (*(code *)0x19892)();
  iVar3 = (*(code *)0x19876)();
  if (iVar3 == 0) {
    _DAT_0041ac20 = _DAT_0041ac20 & -(uint)(iVar2 == 1);
  }
  return;
}



// Library Function - Single Match
//  ___scrt_get_show_window_mode
// 
// Library: Visual Studio 2015 Release

undefined2 ___scrt_get_show_window_mode(void)

{
  undefined1 local_48 [44];
  byte local_1c;
  undefined2 local_18;
  
  _memset(local_48,0,0x44);
  (*(code *)0x198b0)(local_48);
  if ((local_1c & 1) == 0) {
    local_18 = 10;
  }
  return local_18;
}



void FUN_00409e1b(void)

{
  (*(code *)0x19892)(___scrt_unhandled_exception_filter_4);
  return;
}



// Library Function - Single Match
//  ___scrt_unhandled_exception_filter@4
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

undefined4 ___scrt_unhandled_exception_filter_4(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)*param_1;
  if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
     ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
      (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
                    // WARNING: Subroutine does not return
    terminate();
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00409e68(void)

{
  _DAT_0041ac20 = 0;
  return;
}



// WARNING: Removing unreachable block (ram,0x00409e80)
// WARNING: Removing unreachable block (ram,0x00409e81)
// WARNING: Removing unreachable block (ram,0x00409e87)
// WARNING: Removing unreachable block (ram,0x00409e90)
// WARNING: Removing unreachable block (ram,0x00409e97)

void FUN_00409e70(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00409eab)
// WARNING: Removing unreachable block (ram,0x00409eac)
// WARNING: Removing unreachable block (ram,0x00409eb2)
// WARNING: Removing unreachable block (ram,0x00409ebb)
// WARNING: Removing unreachable block (ram,0x00409ec2)

void FUN_00409e9b(void)

{
  return;
}



void __cdecl guard_check_icall(void)

{
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined1 local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0041a208 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



void * __thiscall FUN_00409f2b(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = std::bad_alloc::vftable;
  return this;
}



undefined4 * __fastcall FUN_00409f46(undefined4 *param_1)

{
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



void * __thiscall FUN_00409f5e(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = std::bad_array_new_length::vftable;
  return this;
}



undefined4 * __fastcall FUN_00409f79(undefined4 *param_1)

{
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined ***)this = vftable;
  *(undefined4 *)(this + 4) = 0;
  *(undefined4 *)(this + 8) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 4),(undefined4 *)(this + 4));
  return this;
}



void * __thiscall FUN_00409fce(void *this,byte param_1)

{
  *(undefined ***)this = std::exception::vftable;
  ___std_exception_destroy((undefined4 *)((int)this + 4));
  if ((param_1 & 1) != 0) {
    FUN_0040a200(this);
  }
  return this;
}



// Library Function - Multiple Matches With Different Base Names
//  void __cdecl __scrt_throw_std_bad_alloc(void)
//  void __cdecl __scrt_throw_std_bad_array_new_length(void)
// 
// Library: Visual Studio 2015 Release

void FID_conflict___scrt_throw_std_bad_alloc(void)

{
  int local_10 [3];
  
  FUN_00409f46(local_10);
                    // WARNING: Subroutine does not return
  __CxxThrowException_8(local_10,&DAT_004191e4);
}



// Library Function - Multiple Matches With Different Base Names
//  void __cdecl __scrt_throw_std_bad_alloc(void)
//  void __cdecl __scrt_throw_std_bad_array_new_length(void)
// 
// Library: Visual Studio 2015 Release

void FID_conflict___scrt_throw_std_bad_alloc(void)

{
  int local_10 [3];
  
  FUN_00409f79(local_10);
                    // WARNING: Subroutine does not return
  __CxxThrowException_8(local_10,&DAT_00419238);
}



char * __fastcall FUN_0040a035(int param_1)

{
  char *pcVar1;
  
  pcVar1 = *(char **)(param_1 + 4);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "Unknown exception";
  }
  return pcVar1;
}



// WARNING: Removing unreachable block (ram,0x0040a083)
// WARNING: Removing unreachable block (ram,0x0040a13a)
// WARNING: Removing unreachable block (ram,0x0040a0c4)

undefined4 FUN_0040a042(void)

{
  int *piVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint in_XCR0;
  uint local_18;
  
  DAT_0041ac24 = 0;
  DAT_0041a200 = DAT_0041a200 | 1;
  iVar4 = FUN_00412d36();
  uVar3 = DAT_0041a200;
  if (iVar4 != 0) {
    local_18 = 0;
    DAT_0041a200 = DAT_0041a200 | 2;
    DAT_0041ac24 = 1;
    piVar1 = (int *)cpuid_basic_info(0);
    puVar2 = (uint *)cpuid_Version_info(1);
    uVar6 = puVar2[3];
    if (((piVar1[2] == 0x49656e69 && piVar1[3] == 0x6c65746e) && piVar1[1] == 0x756e6547) &&
       (((((uVar5 = *puVar2 & 0xfff3ff0, uVar5 == 0x106c0 || (uVar5 == 0x20660)) ||
          (uVar5 == 0x20670)) || ((uVar5 == 0x30650 || (uVar5 == 0x30660)))) || (uVar5 == 0x30670)))
       ) {
      DAT_0041ac28 = DAT_0041ac28 | 1;
    }
    if (6 < *piVar1) {
      iVar4 = cpuid_Extended_Feature_Enumeration_info(7);
      local_18 = *(uint *)(iVar4 + 4);
      if ((local_18 & 0x200) != 0) {
        DAT_0041ac28 = DAT_0041ac28 | 2;
      }
    }
    if ((uVar6 & 0x100000) != 0) {
      DAT_0041a200 = uVar3 | 6;
      DAT_0041ac24 = 2;
      if ((((uVar6 & 0x8000000) != 0) && ((uVar6 & 0x10000000) != 0)) && ((in_XCR0 & 6) == 6)) {
        DAT_0041a200 = uVar3 | 0xe;
        DAT_0041ac24 = 3;
        if ((local_18 & 0x20) != 0) {
          DAT_0041a200 = uVar3 | 0x2e;
          DAT_0041ac24 = 5;
        }
      }
    }
  }
  return 0;
}



// Library Function - Single Match
//  ___scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2015 Release

bool ___scrt_is_ucrt_dll_in_use(void)

{
  return DAT_0041b5f4 != 0;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Library: Visual Studio 2015 Release

void __fastcall __security_check_cookie(uintptr_t _StackCookie)

{
  if (_StackCookie == DAT_0041a208) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



void __cdecl FUN_0040a200(void *param_1)

{
  FID_conflict__free(param_1);
  return;
}



void * __thiscall FUN_0040a20e(void *this,byte param_1)

{
  *(undefined ***)this = type_info::vftable;
  if ((param_1 & 1) != 0) {
    FUN_0040a200(this);
  }
  return this;
}



// Library Function - Single Match
//  ___raise_securityfailure
// 
// Library: Visual Studio 2015 Release

void __cdecl ___raise_securityfailure(undefined4 param_1)

{
  undefined4 uVar1;
  
  (*(code *)0x19892)(0);
  (*(code *)0x19876)(param_1);
  uVar1 = (*(code *)0x198f2)(0xc0000409);
  (*(code *)0x19906)(uVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Library: Visual Studio 2015 Release

void __cdecl ___report_gsfailure(void)

{
  code *pcVar1;
  uint uVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar3;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte bVar4;
  byte bVar5;
  byte in_AF;
  byte bVar6;
  byte bVar7;
  byte in_TF;
  byte in_IF;
  byte bVar8;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined8 uVar9;
  undefined4 unaff_retaddr;
  
  uVar9 = FUN_00412d36();
  uVar2 = (uint)uVar9;
  bVar4 = 0;
  bVar8 = 0;
  bVar7 = (int)uVar2 < 0;
  bVar6 = uVar2 == 0;
  bVar5 = (POPCOUNT(uVar2 & 0xff) & 1U) == 0;
  uVar3 = extraout_ECX;
  if (!(bool)bVar6) {
    pcVar1 = (code *)swi(0x29);
    uVar9 = (*pcVar1)();
    uVar3 = extraout_ECX_00;
  }
  _DAT_0041ad28 = (undefined4)((ulonglong)uVar9 >> 0x20);
  _DAT_0041ad30 = (undefined4)uVar9;
  _DAT_0041ad40 =
       (uint)(in_NT & 1) * 0x4000 | (uint)(bVar8 & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)(bVar7 & 1) * 0x80 | (uint)(bVar6 & 1) * 0x40 |
       (uint)(in_AF & 1) * 0x10 | (uint)(bVar5 & 1) * 4 | (uint)(bVar4 & 1) |
       (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
       (uint)(in_AC & 1) * 0x40000;
  _DAT_0041ad44 = &stack0x00000004;
  _DAT_0041ac80 = 0x10001;
  _DAT_0041ac30 = 0xc0000409;
  _DAT_0041ac34 = 1;
  _DAT_0041ac40 = 1;
  DAT_0041ac44 = 2;
  _DAT_0041ac3c = unaff_retaddr;
  _DAT_0041ad0c = in_GS;
  _DAT_0041ad10 = in_FS;
  _DAT_0041ad14 = in_ES;
  _DAT_0041ad18 = in_DS;
  _DAT_0041ad1c = unaff_EDI;
  _DAT_0041ad20 = unaff_ESI;
  _DAT_0041ad24 = unaff_EBX;
  _DAT_0041ad2c = uVar3;
  _DAT_0041ad34 = unaff_EBP;
  DAT_0041ad38 = unaff_retaddr;
  _DAT_0041ad3c = in_CS;
  _DAT_0041ad48 = in_SS;
  ___raise_securityfailure(&PTR_DAT_004142f8);
  return;
}



void __cdecl FID_conflict__free(void *_Memory)

{
  int iVar1;
  int *piVar2;
  ulong uVar3;
  
  if (_Memory != (void *)0x0) {
    iVar1 = (*(code *)0x19abe)(DAT_0041b5d0,0,_Memory);
    if (iVar1 == 0) {
      piVar2 = __errno();
      uVar3 = (*(code *)0x1991a)();
      iVar1 = FID_conflict____acrt_errno_from_os_error(uVar3);
      *piVar2 = iVar1;
    }
  }
  return;
}



void __cdecl FUN_0040a359(undefined4 param_1,undefined2 *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = (*(code *)0x1992a)(param_1,param_2,param_3);
  if (param_3 != 0) {
    if (iVar1 == 0) {
      *param_2 = 0;
    }
    if (iVar1 == param_3) {
      iVar1 = (*(code *)0x1991a)();
      if (iVar1 == 0) {
        param_2[param_3 + -1] = 0;
      }
    }
  }
  return;
}



void __cdecl FUN_0040a393(undefined4 param_1)

{
  uint uVar1;
  undefined4 local_250 [8];
  undefined4 local_230 [4];
  undefined4 local_220 [4];
  short local_210 [260];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  FUN_0040a359(param_1,local_210,0x104);
  if ((5 < DAT_0041a210) && (uVar1 = FUN_0040119b(0x41a210,0,0x2000), (char)uVar1 != '\0')) {
    FUN_004010a7(local_230,"Main Invoked.");
    FUN_004010df(local_220,local_210);
    FUN_004011d7(0x41a210,(undefined4 *)&DAT_00418d99,0,0,4,local_250);
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_0040a42f(undefined4 param_1)

{
  uint uVar1;
  undefined4 local_250 [8];
  undefined4 local_230 [4];
  undefined4 local_220 [4];
  short local_210 [260];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  FUN_0040a359(param_1,local_210,0x104);
  if ((5 < DAT_0041a210) && (uVar1 = FUN_0040119b(0x41a210,0,0x2000), (char)uVar1 != '\0')) {
    FUN_004010a7(local_230,"Main Returned.");
    FUN_004010df(local_220,local_210);
    FUN_004011d7(0x41a210,(undefined4 *)&DAT_00418dd5,0,0,4,local_250);
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040a4cb(void)

{
  FUN_00401000(0x41a210,0,0,0);
  return;
}



void FUN_0040a4de(void)

{
  FUN_00401088(0x41a210);
  return;
}



// Library Function - Single Match
//  _ValidateLocalCookies
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl _ValidateLocalCookies(int *param_1,int param_2)

{
  if (*param_1 != -2) {
    __security_check_cookie(param_1[1] + param_2 ^ *(uint *)(*param_1 + param_2));
  }
  __security_check_cookie(param_1[3] + param_2 ^ *(uint *)(param_1[2] + param_2));
  return;
}



undefined4 __cdecl FUN_0040a530(int *param_1,int param_2,undefined4 param_3)

{
  uint uVar1;
  code *pcVar2;
  int iVar3;
  BOOL BVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  int *local_20;
  undefined4 local_1c;
  int *local_18;
  int local_14;
  undefined4 local_10;
  int *local_c;
  char local_5;
  
  local_5 = '\0';
  iVar5 = param_2 + 0x10;
  local_c = (int *)(*(uint *)(param_2 + 8) ^ DAT_0041a208);
  local_10 = 1;
  local_14 = iVar5;
  _ValidateLocalCookies(local_c,iVar5);
  guard_check_icall();
  if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
    local_20 = param_1;
    local_1c = param_3;
    *(int ***)(param_2 + -4) = &local_20;
    uVar6 = *(uint *)(param_2 + 0xc);
    if (*(uint *)(param_2 + 0xc) == 0xfffffffe) {
      return local_10;
    }
    do {
      iVar3 = uVar6 * 3 + 4;
      uVar1 = local_c[iVar3];
      local_18 = local_c + iVar3;
      if ((undefined *)local_18[1] != (undefined *)0x0) {
        iVar3 = _EH4_CallFilterFunc((undefined *)local_18[1]);
        local_5 = '\x01';
        if (iVar3 < 0) {
          local_10 = 0;
          goto LAB_0040a645;
        }
        if (0 < iVar3) {
          if (((*param_1 == -0x1f928c9d) && (DAT_0041b600 != (code *)0x0)) &&
             (BVar4 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041b600), pcVar2 = DAT_0041b600,
             BVar4 != 0)) {
            uVar7 = 1;
            guard_check_icall();
            (*pcVar2)(param_1,uVar7);
            iVar5 = local_14;
          }
          FUN_0040adce();
          if (*(uint *)(param_2 + 0xc) != uVar6) {
            _EH4_LocalUnwind(param_2,uVar6,iVar5,&DAT_0041a208);
          }
          *(uint *)(param_2 + 0xc) = uVar1;
          _ValidateLocalCookies(local_c,iVar5);
          _EH4_TransferToHandler((undefined *)local_18[2]);
          pcVar2 = (code *)swi(3);
          uVar7 = (*pcVar2)();
          return uVar7;
        }
      }
      uVar6 = uVar1;
    } while (uVar1 != 0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
    if (*(int *)(param_2 + 0xc) == -2) {
      return local_10;
    }
    _EH4_LocalUnwind(param_2,0xfffffffe,iVar5,&DAT_0041a208);
  }
LAB_0040a645:
  _ValidateLocalCookies(local_c,iVar5);
  return local_10;
}



uint FUN_0040a68a(void)

{
  uint uVar1;
  undefined4 uVar2;
  
  FUN_0040aed3();
  FUN_0040ac48();
  uVar1 = ___vcrt_initialize_locks();
  if ((char)uVar1 != '\0') {
    uVar2 = ___vcrt_initialize_ptd();
    if ((char)uVar2 != '\0') {
      uVar2 = FUN_0040a4cb();
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
    uVar1 = ___vcrt_uninitialize_locks();
  }
  return uVar1 & 0xffffff00;
}



undefined4 __cdecl FUN_0040a6b8(char param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_0040a4de();
  if (param_1 == '\0') {
    ___vcrt_uninitialize_ptd();
    ___vcrt_uninitialize_locks();
    uVar1 = ___vcrt_uninitialize_winapi_thunks('\0');
  }
  return CONCAT31((int3)((uint)uVar1 >> 8),1);
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  int iVar1;
  undefined1 *puVar2;
  int *piVar3;
  
  if (_Size == 0) {
    return _Dst;
  }
  iVar1 = (_Val & 0xffU) * 0x1010101;
  piVar3 = (int *)_Dst;
  if (0x20 < (int)_Size) {
    if (0x7f < (int)_Size) {
      puVar2 = (undefined1 *)_Dst;
      if ((DAT_0041ac28 >> 1 & 1) != 0) {
        for (; _Size != 0; _Size = _Size - 1) {
          *puVar2 = (char)iVar1;
          puVar2 = puVar2 + 1;
        }
        return _Dst;
      }
      if ((DAT_0041a200 >> 1 & 1) == 0) goto joined_r0x0040a7eb;
      *(int *)_Dst = iVar1;
      *(int *)((int)_Dst + 4) = iVar1;
      *(int *)((int)_Dst + 8) = iVar1;
      *(int *)((int)_Dst + 0xc) = iVar1;
      piVar3 = (int *)((int)_Dst + 0x10U & 0xfffffff0);
      _Size = (int)_Dst + (_Size - (int)piVar3);
      if (0x80 < (int)_Size) {
        do {
          *piVar3 = iVar1;
          piVar3[1] = iVar1;
          piVar3[2] = iVar1;
          piVar3[3] = iVar1;
          piVar3[4] = iVar1;
          piVar3[5] = iVar1;
          piVar3[6] = iVar1;
          piVar3[7] = iVar1;
          piVar3[8] = iVar1;
          piVar3[9] = iVar1;
          piVar3[10] = iVar1;
          piVar3[0xb] = iVar1;
          piVar3[0xc] = iVar1;
          piVar3[0xd] = iVar1;
          piVar3[0xe] = iVar1;
          piVar3[0xf] = iVar1;
          piVar3[0x10] = iVar1;
          piVar3[0x11] = iVar1;
          piVar3[0x12] = iVar1;
          piVar3[0x13] = iVar1;
          piVar3[0x14] = iVar1;
          piVar3[0x15] = iVar1;
          piVar3[0x16] = iVar1;
          piVar3[0x17] = iVar1;
          piVar3[0x18] = iVar1;
          piVar3[0x19] = iVar1;
          piVar3[0x1a] = iVar1;
          piVar3[0x1b] = iVar1;
          piVar3[0x1c] = iVar1;
          piVar3[0x1d] = iVar1;
          piVar3[0x1e] = iVar1;
          piVar3[0x1f] = iVar1;
          piVar3 = piVar3 + 0x20;
          _Size = _Size - 0x80;
        } while ((_Size & 0xffffff00) != 0);
        goto LAB_0040a7b0;
      }
    }
    if ((DAT_0041a200 >> 1 & 1) != 0) {
LAB_0040a7b0:
      if (0x1f < _Size) {
        do {
          *piVar3 = iVar1;
          piVar3[1] = iVar1;
          piVar3[2] = iVar1;
          piVar3[3] = iVar1;
          piVar3[4] = iVar1;
          piVar3[5] = iVar1;
          piVar3[6] = iVar1;
          piVar3[7] = iVar1;
          piVar3 = piVar3 + 8;
          _Size = _Size - 0x20;
        } while (0x1f < _Size);
        if ((_Size & 0x1f) == 0) {
          return _Dst;
        }
      }
      piVar3 = (int *)((_Size - 0x20) + (int)piVar3);
      *piVar3 = iVar1;
      piVar3[1] = iVar1;
      piVar3[2] = iVar1;
      piVar3[3] = iVar1;
      piVar3[4] = iVar1;
      piVar3[5] = iVar1;
      piVar3[6] = iVar1;
      piVar3[7] = iVar1;
      return _Dst;
    }
  }
joined_r0x0040a7eb:
  for (; (_Size & 3) != 0; _Size = _Size - 1) {
    *(char *)piVar3 = (char)iVar1;
    piVar3 = (int *)((int)piVar3 + 1);
  }
  if ((_Size & 4) != 0) {
    *piVar3 = iVar1;
    piVar3 = piVar3 + 1;
    _Size = _Size - 4;
  }
  for (; (_Size & 0xfffffff8) != 0; _Size = _Size - 8) {
    *piVar3 = iVar1;
    piVar3[1] = iVar1;
    piVar3 = piVar3 + 2;
  }
  return _Dst;
}



// Library Function - Single Match
//  ___std_exception_copy
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___std_exception_copy(undefined4 *param_1,undefined4 *param_2)

{
  char *pcVar1;
  char cVar2;
  char *_Dst;
  char *pcVar3;
  char *_Memory;
  
  if ((*(char *)(param_1 + 1) == '\0') || (pcVar3 = (char *)*param_1, pcVar3 == (char *)0x0)) {
    *param_2 = *param_1;
    *(undefined1 *)(param_2 + 1) = 0;
  }
  else {
    pcVar1 = pcVar3 + 1;
    do {
      cVar2 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar2 != '\0');
    _Dst = (char *)FUN_0040bfdd((size_t)(pcVar3 + (1 - (int)pcVar1)));
    _Memory = _Dst;
    if (_Dst != (char *)0x0) {
      _strcpy_s(_Dst,(rsize_t)(pcVar3 + (1 - (int)pcVar1)),(char *)*param_1);
      _Memory = (char *)0x0;
      *param_2 = _Dst;
      *(undefined1 *)(param_2 + 1) = 1;
    }
    FID_conflict__free(_Memory);
  }
  return;
}



// Library Function - Single Match
//  ___std_exception_destroy
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___std_exception_destroy(undefined4 *param_1)

{
  if (*(char *)(param_1 + 1) != '\0') {
    FID_conflict__free((void *)*param_1);
  }
  *param_1 = 0;
  *(undefined1 *)(param_1 + 1) = 0;
  return;
}



// Library Function - Single Match
//  __CxxThrowException@8
// 
// Library: Visual Studio 2015 Release

void __CxxThrowException_8(int *param_1,byte *param_2)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 local_24 [4];
  undefined4 local_14;
  undefined4 local_10;
  int *local_c;
  byte *local_8;
  
  puVar4 = &DAT_0041432c;
  puVar5 = local_24;
  for (iVar2 = 8; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  if ((param_2 != (byte *)0x0) && ((*param_2 & 0x10) != 0)) {
    piVar3 = (int *)(*param_1 + -4);
    pcVar1 = *(code **)(*piVar3 + 0x20);
    param_2 = *(byte **)(*piVar3 + 0x18);
    guard_check_icall();
    (*pcVar1)(piVar3);
  }
  local_c = param_1;
  if ((param_2 != (byte *)0x0) && ((*param_2 & 8) != 0)) {
    local_10 = 0x1994000;
  }
  local_8 = param_2;
  (*(code *)0x19940)(local_24[0],local_24[1],local_14,&local_10);
  return;
}



// Library Function - Single Match
//  void * __cdecl try_get_function(enum `anonymous namespace'::function_id,char const * const,enum
// A0x89697e75::module_id const * const,enum A0x89697e75::module_id const * const)
// 
// Library: Visual Studio 2015 Release

void * __cdecl
try_get_function(function_id param_1,char *param_2,module_id *param_3,module_id *param_4)

{
  uint *puVar1;
  uint uVar2;
  HINSTANCE__ *pHVar3;
  void *pvVar4;
  byte bVar5;
  void *pvVar6;
  
  puVar1 = &DAT_0041af5c + param_1;
  LOCK();
  uVar2 = *puVar1;
  if (uVar2 == 0) {
    *puVar1 = 0;
    uVar2 = 0;
  }
  UNLOCK();
  bVar5 = (byte)DAT_0041a208 & 0x1f;
  pvVar6 = (void *)((DAT_0041a208 ^ uVar2) >> bVar5 | (DAT_0041a208 ^ uVar2) << 0x20 - bVar5);
  if (pvVar6 != (void *)0xffffffff) {
    if (pvVar6 != (void *)0x0) {
      return pvVar6;
    }
    if (param_3 != param_4) {
      do {
        pHVar3 = try_get_module(*param_3);
        if (pHVar3 != (HINSTANCE__ *)0x0) goto LAB_0040a986;
        param_3 = param_3 + 1;
      } while (param_3 != param_4);
    }
    pHVar3 = (HINSTANCE__ *)0x0;
LAB_0040a986:
    if ((pHVar3 != (HINSTANCE__ *)0x0) &&
       (pvVar6 = (void *)(*(code *)0x199ba)(pHVar3,param_2), pvVar6 != (void *)0x0)) {
      pvVar4 = __crt_fast_encode_pointer<void*>(pvVar6);
      LOCK();
      *puVar1 = (uint)pvVar4;
      UNLOCK();
      return pvVar6;
    }
    bVar5 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
    LOCK();
    *puVar1 = (0xffffffffU >> bVar5 | -1 << 0x20 - bVar5) ^ DAT_0041a208;
    UNLOCK();
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  struct HINSTANCE__ * __cdecl try_get_module(enum `anonymous namespace'::module_id)
// 
// Library: Visual Studio 2015 Release

HINSTANCE__ * __cdecl try_get_module(module_id param_1)

{
  uint *puVar1;
  undefined *puVar2;
  uint uVar3;
  HINSTANCE__ *pHVar4;
  int iVar5;
  
  puVar1 = &DAT_0041af4c + param_1;
  LOCK();
  uVar3 = *puVar1;
  if (uVar3 == 0) {
    *puVar1 = 0;
    uVar3 = 0;
  }
  UNLOCK();
  if (uVar3 == 0) {
    puVar2 = (&PTR_u_advapi32_0041434c)[param_1];
    pHVar4 = (HINSTANCE__ *)(*(code *)0x199cc)(puVar2,0,0x800);
    if (pHVar4 == (HINSTANCE__ *)0x0) {
      iVar5 = (*(code *)0x1991a)();
      if (iVar5 == 0x57) {
        pHVar4 = (HINSTANCE__ *)(*(code *)0x199cc)(puVar2,0,0);
      }
      else {
        pHVar4 = (HINSTANCE__ *)0x0;
      }
      if (pHVar4 == (HINSTANCE__ *)0x0) {
        LOCK();
        *puVar1 = 0xffffffff;
        UNLOCK();
        return (HINSTANCE__ *)0x0;
      }
    }
    LOCK();
    uVar3 = *puVar1;
    *puVar1 = (uint)pHVar4;
    UNLOCK();
    if (uVar3 != 0) {
      (*(code *)0x199ac)(pHVar4);
    }
  }
  else {
    pHVar4 = (HINSTANCE__ *)(-(uint)(uVar3 != 0xffffffff) & uVar3);
  }
  return pHVar4;
}



// Library Function - Single Match
//  ___vcrt_EventRegister
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl
___vcrt_EventRegister(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  code *pcVar1;
  undefined4 uVar2;
  
  pcVar1 = (code *)try_get_function(0,"EventRegister",(module_id *)&DAT_004143fc,
                                    (module_id *)"EventRegister");
  if (pcVar1 == (code *)0x0) {
    uVar2 = 0x32;
  }
  else {
    guard_check_icall();
    uVar2 = (*pcVar1)(param_1,param_2,param_3,param_4);
  }
  return uVar2;
}



// Library Function - Single Match
//  ___vcrt_EventSetInformation
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl
___vcrt_EventSetInformation
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  code *pcVar1;
  undefined4 uVar2;
  
  pcVar1 = (code *)try_get_function(1,"EventSetInformation",(module_id *)&DAT_00414410,
                                    (module_id *)"EventSetInformation");
  if (pcVar1 == (code *)0x0) {
    uVar2 = 0x32;
  }
  else {
    guard_check_icall();
    uVar2 = (*pcVar1)(param_1,param_2,param_3,param_4,param_5);
  }
  return uVar2;
}



// Library Function - Single Match
//  ___vcrt_EventUnregister
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl ___vcrt_EventUnregister(undefined4 param_1,undefined4 param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  
  pcVar1 = (code *)try_get_function(2,"EventUnregister",(module_id *)&DAT_00414428,
                                    (module_id *)"EventUnregister");
  if (pcVar1 == (code *)0x0) {
    uVar2 = 0x32;
  }
  else {
    guard_check_icall();
    uVar2 = (*pcVar1)(param_1,param_2);
  }
  return uVar2;
}



// Library Function - Single Match
//  ___vcrt_EventWriteTransfer
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl
___vcrt_EventWriteTransfer
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  code *pcVar1;
  undefined4 uVar2;
  
  pcVar1 = (code *)try_get_function(3,"EventWriteTransfer",(module_id *)&DAT_0041443c,
                                    (module_id *)"EventWriteTransfer");
  if (pcVar1 == (code *)0x0) {
    uVar2 = 0x32;
  }
  else {
    guard_check_icall();
    uVar2 = (*pcVar1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  }
  return uVar2;
}



// Library Function - Single Match
//  ___vcrt_FlsAlloc
// 
// Library: Visual Studio 2015 Release

void __cdecl ___vcrt_FlsAlloc(undefined4 param_1)

{
  code *pcVar1;
  
  pcVar1 = (code *)try_get_function(4,"FlsAlloc",(module_id *)&DAT_00414454,(module_id *)"FlsAlloc")
  ;
  if (pcVar1 != (code *)0x0) {
    guard_check_icall();
    (*pcVar1)(param_1);
    return;
  }
  (*(code *)0x1997a)();
  return;
}



// Library Function - Single Match
//  ___vcrt_FlsFree
// 
// Library: Visual Studio 2015 Release

void __cdecl ___vcrt_FlsFree(undefined4 param_1)

{
  code *pcVar1;
  
  pcVar1 = (code *)try_get_function(5,"FlsFree",(module_id *)&DAT_00414468,(module_id *)"FlsFree");
  if (pcVar1 == (code *)0x0) {
    (*(code *)0x199a2)(param_1);
  }
  else {
    guard_check_icall();
    (*pcVar1)();
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_FlsSetValue
// 
// Library: Visual Studio 2015 Release

void __cdecl ___vcrt_FlsSetValue(undefined4 param_1,undefined4 param_2)

{
  code *pcVar1;
  
  pcVar1 = (code *)try_get_function(7,"FlsSetValue",(module_id *)&DAT_00414484,
                                    (module_id *)"FlsSetValue");
  if (pcVar1 == (code *)0x0) {
    (*(code *)0x19994)(param_1,param_2);
  }
  else {
    guard_check_icall();
    (*pcVar1)();
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_InitializeCriticalSectionEx
// 
// Library: Visual Studio 2015 Release

void __cdecl
___vcrt_InitializeCriticalSectionEx(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)try_get_function(8,"InitializeCriticalSectionEx",(module_id *)&DAT_00414498,
                                    (module_id *)"InitializeCriticalSectionEx");
  if (pcVar1 == (code *)0x0) {
    (*(code *)0x19952)(param_1,param_2);
  }
  else {
    guard_check_icall();
    (*pcVar1)(param_1,param_2,param_3);
  }
  return;
}



void FUN_0040ac48(void)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  
  bVar1 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
  uVar2 = (0U >> bVar1 | 0 << 0x20 - bVar1) ^ DAT_0041a208;
  puVar4 = &DAT_0041af5c;
  for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = uVar2;
    puVar4 = puVar4 + 1;
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_uninitialize_winapi_thunks
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __cdecl ___vcrt_uninitialize_winapi_thunks(char param_1)

{
  int *piVar1;
  
  if (param_1 == '\0') {
    piVar1 = &DAT_0041af4c;
    do {
      if (*piVar1 != 0) {
        if (*piVar1 != -1) {
          (*(code *)0x199ac)(*piVar1);
        }
        *piVar1 = 0;
      }
      piVar1 = piVar1 + 1;
    } while (piVar1 != &DAT_0041af5c);
  }
  return;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  void *pvStack_28;
  undefined1 *puStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  puStack_24 = &LAB_0040ad30;
  pvStack_28 = ExceptionList;
  local_20 = DAT_0041a208 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_0040b034();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio

void __fastcall _EH4_CallFilterFunc(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __fastcall _EH4_TransferToHandler(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x0040adcc. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_0040adce(void)

{
  FUN_00412d3c();
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio

void __fastcall _EH4_LocalUnwind(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



void FUN_0040adfe(undefined *param_1)

{
  if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_0041af80)) {
    FID_conflict__free(param_1);
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_initialize_ptd
// 
// Library: Visual Studio 2015 Release

uint ___vcrt_initialize_ptd(void)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = ___vcrt_FlsAlloc(FUN_0040adfe);
  DAT_0041a250 = uVar1;
  if (uVar1 != 0xffffffff) {
    iVar2 = ___vcrt_FlsSetValue(uVar1,&DAT_0041af80);
    if (iVar2 != 0) {
      return CONCAT31((int3)((uint)iVar2 >> 8),1);
    }
    uVar1 = ___vcrt_uninitialize_ptd();
  }
  return uVar1 & 0xffffff00;
}



// Library Function - Single Match
//  ___vcrt_uninitialize_ptd
// 
// Library: Visual Studio 2015 Release

undefined4 ___vcrt_uninitialize_ptd(void)

{
  int iVar1;
  
  iVar1 = DAT_0041a250;
  if (DAT_0041a250 != -1) {
    iVar1 = ___vcrt_FlsFree(DAT_0041a250);
    DAT_0041a250 = -1;
  }
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



// Library Function - Single Match
//  ___vcrt_initialize_locks
// 
// Library: Visual Studio 2015 Release

undefined4 ___vcrt_initialize_locks(void)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  
  puVar3 = &DAT_0041afa8;
  uVar2 = 0;
  do {
    iVar1 = ___vcrt_InitializeCriticalSectionEx(puVar3,4000,0);
    if (iVar1 == 0) {
      uVar2 = ___vcrt_uninitialize_locks();
      return uVar2 & 0xffffff00;
    }
    DAT_0041afc0 = DAT_0041afc0 + 1;
    uVar2 = uVar2 + 0x18;
    puVar3 = puVar3 + 0x18;
  } while (uVar2 < 0x18);
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



// Library Function - Single Match
//  ___vcrt_uninitialize_locks
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 ___vcrt_uninitialize_locks(void)

{
  undefined4 in_EAX;
  int iVar1;
  undefined *puVar2;
  
  if (DAT_0041afc0 != 0) {
    puVar2 = &DAT_0041af90 + DAT_0041afc0 * 0x18;
    iVar1 = DAT_0041afc0;
    do {
      in_EAX = (*(code *)0x19a2a)(puVar2);
      DAT_0041afc0 = DAT_0041afc0 + -1;
      puVar2 = puVar2 + -0x18;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040aed3(void)

{
  byte bVar1;
  
  bVar1 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
  _DAT_0041afc4 = (0U >> bVar1 | 0 << 0x20 - bVar1) ^ DAT_0041a208;
  return;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __global_unwind2(void)

{
  FUN_00412d3c();
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind2(int param_1,uint param_2)

{
  uint uVar1;
  void *local_20;
  undefined1 *puStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  puStack_1c = &LAB_0040af20;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_0040b034();
    }
  }
  ExceptionList = local_20;
  return;
}



// Library Function - Single Match
//  __NLG_Notify
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __NLG_Notify(ulong param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_0041a268 = param_1;
  DAT_0041a264 = in_EAX;
  DAT_0041a26c = unaff_EBP;
  return;
}



void FUN_0040b034(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2015 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
    iVar2 = -1;
  }
  else {
    iVar2 = -1;
    if (((uint)_File->_flag >> 0xd & 1) != 0) {
      iVar2 = ___acrt_stdio_flush_nolock(_File);
      ___acrt_stdio_free_buffer_nolock(&_File->_ptr);
      iVar3 = __fileno(_File);
      iVar3 = __close(iVar3);
      if (iVar3 < 0) {
        iVar2 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        FID_conflict__free(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    __acrt_stdio_free_stream(_File);
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fclose
// 
// Library: Visual Studio 2015 Release

int __cdecl _fclose(FILE *_File)

{
  int *piVar1;
  int iVar2;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
  }
  else {
    if (((uint)_File->_flag >> 0xc & 1) == 0) {
      __lock_file(_File);
      iVar2 = __fclose_nolock(_File);
      FUN_0040b123();
      return iVar2;
    }
    __acrt_stdio_free_stream();
  }
  return -1;
}



void FUN_0040b123(void)

{
  int unaff_EBP;
  
  FUN_0040cd57(*(int *)(unaff_EBP + -0x20));
  return;
}



// Library Function - Single Match
//  ___acrt_stdio_flush_nolock
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl ___acrt_stdio_flush_nolock(FILE *param_1)

{
  int *piVar1;
  int _FileHandle;
  uint uVar2;
  uint uVar3;
  char *_Buf;
  
  piVar1 = &param_1->_flag;
  if ((((byte)*piVar1 & 3) == 2) && ((*piVar1 & 0xc0U) != 0)) {
    _Buf = (char *)param_1->_cnt;
    uVar3 = (int)param_1->_ptr - (int)_Buf;
    param_1->_ptr = _Buf;
    param_1->_base = (char *)0x0;
    if (0 < (int)uVar3) {
      uVar2 = uVar3;
      _FileHandle = __fileno(param_1);
      uVar2 = __write(_FileHandle,_Buf,uVar2);
      if (uVar3 != uVar2) {
        LOCK();
        *piVar1 = *piVar1 | 0x10;
        UNLOCK();
        return 0xffffffff;
      }
      if (((uint)*piVar1 >> 2 & 1) != 0) {
        LOCK();
        *piVar1 = *piVar1 & 0xfffffffd;
        UNLOCK();
      }
    }
  }
  return 0;
}



// Library Function - Single Match
//  __fflush_nolock
// 
// Library: Visual Studio 2015 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  
  if (_File == (FILE *)0x0) {
    iVar1 = common_flush_all(0);
    return iVar1;
  }
  iVar1 = ___acrt_stdio_flush_nolock(_File);
  if (iVar1 == 0) {
    if (((uint)_File->_flag >> 0xb & 1) != 0) {
      iVar1 = __fileno(_File);
      iVar1 = __commit(iVar1);
      if (iVar1 != 0) goto LAB_0040b1b4;
    }
    iVar1 = 0;
  }
  else {
LAB_0040b1b4:
    iVar1 = -1;
  }
  return iVar1;
}



// Library Function - Single Match
//  __flushall
// 
// Library: Visual Studio 2015 Release

int __cdecl __flushall(void)

{
  int iVar1;
  
  iVar1 = common_flush_all(1);
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _common_flush_all
// 
// Library: Visual Studio 2015 Release

int __cdecl common_flush_all(int param_1)

{
  undefined4 *puVar1;
  FILE *_File;
  int iVar2;
  undefined4 *puVar3;
  int local_28;
  int local_20;
  
  local_20 = 0;
  local_28 = 0;
  ___acrt_lock(8);
  puVar1 = DAT_0041b168 + DAT_0041b164;
  for (puVar3 = DAT_0041b168; puVar3 != puVar1; puVar3 = puVar3 + 1) {
    _File = (FILE *)*puVar3;
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      if (((uint)_File->_flag >> 0xd & 1) != 0) {
        if (param_1 == 1) {
          iVar2 = __fflush_nolock(_File);
          if (iVar2 != -1) {
            local_20 = local_20 + 1;
          }
        }
        else if ((param_1 == 0) && (((uint)_File->_flag >> 1 & 1) != 0)) {
          iVar2 = __fflush_nolock(_File);
          if (iVar2 == -1) {
            local_28 = -1;
          }
        }
      }
      FUN_0040b288();
    }
  }
  FUN_0040b2b2();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_0040b288(void)

{
  int unaff_EBP;
  
  FUN_0040cd57(*(int *)(unaff_EBP + -0x28));
  return;
}



void FUN_0040b2b2(void)

{
  ___acrt_unlock(8);
  return;
}



// Library Function - Single Match
//  __seh_filter_exe
// 
// Library: Visual Studio 2015 Release

void __cdecl __seh_filter_exe(uint param_1,undefined4 param_2)

{
  uint *puVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  __acrt_ptd *p_Var6;
  uint *puVar7;
  uint *puVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  uint uVar11;
  
  uVar5 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  p_Var6 = ___acrt_getptd_noexit();
  if (p_Var6 != (__acrt_ptd *)0x0) {
    puVar1 = *(uint **)p_Var6;
    for (puVar8 = puVar1; puVar8 != puVar1 + 0x24; puVar8 = puVar8 + 3) {
      if (*puVar8 == param_1) goto LAB_0040b357;
    }
    puVar8 = (uint *)0x0;
LAB_0040b357:
    if ((puVar8 != (uint *)0x0) && (pcVar2 = (code *)puVar8[2], pcVar2 != (code *)0x0)) {
      if (pcVar2 == (code *)0x5) {
        puVar8[2] = 0;
      }
      else if (pcVar2 != (code *)0x1) {
        uVar3 = *(undefined4 *)(p_Var6 + 4);
        *(undefined4 *)(p_Var6 + 4) = param_2;
        if (puVar8[1] == 8) {
          for (puVar7 = puVar1 + 9; puVar7 != puVar1 + 0x24; puVar7 = puVar7 + 3) {
            puVar7[2] = 0;
          }
          uVar4 = *(undefined4 *)(p_Var6 + 8);
          if (*puVar8 < 0xc0000092) {
            if (*puVar8 == 0xc0000091) {
              *(undefined4 *)(p_Var6 + 8) = 0x84;
            }
            else if (*puVar8 == 0xc000008d) {
              *(undefined4 *)(p_Var6 + 8) = 0x82;
            }
            else if (*puVar8 == 0xc000008e) {
              *(undefined4 *)(p_Var6 + 8) = 0x83;
            }
            else if (*puVar8 == 0xc000008f) {
              *(undefined4 *)(p_Var6 + 8) = 0x86;
            }
            else if (*puVar8 == 0xc0000090) {
              *(undefined4 *)(p_Var6 + 8) = 0x81;
            }
          }
          else if (*puVar8 == 0xc0000092) {
            *(undefined4 *)(p_Var6 + 8) = 0x8a;
          }
          else if (*puVar8 == 0xc0000093) {
            *(undefined4 *)(p_Var6 + 8) = 0x85;
          }
          else if (*puVar8 == 0xc00002b4) {
            *(undefined4 *)(p_Var6 + 8) = 0x8e;
          }
          else if (*puVar8 == 0xc00002b5) {
            *(undefined4 *)(p_Var6 + 8) = 0x8d;
          }
          uVar10 = *(undefined4 *)(p_Var6 + 8);
          uVar9 = 8;
          guard_check_icall();
          (*pcVar2)(uVar9,uVar10);
          *(undefined4 *)(p_Var6 + 8) = uVar4;
        }
        else {
          uVar11 = puVar8[1];
          puVar8[2] = 0;
          guard_check_icall();
          (*pcVar2)(uVar11);
        }
        *(undefined4 *)(p_Var6 + 4) = uVar3;
      }
    }
  }
  __security_check_cookie(uVar5 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_0040b487(void)

{
  return DAT_0041b004;
}



void __cdecl FUN_0040b48d(undefined4 param_1)

{
  DAT_0041b004 = param_1;
  return;
}



// Library Function - Single Match
//  public: void __thiscall __crt_state_management::dual_state_global<char * *>::initialize(char * *
// const)
// 
// Library: Visual Studio 2015 Release

void __thiscall
__crt_state_management::dual_state_global<>::initialize
          (dual_state_global<> *this,_func_void_int *param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  uVar1 = ~-(uint)(this + 4 < this) & (uint)(this + 4 + (3 - (int)this)) >> 2;
  if (uVar1 != 0) {
    do {
      uVar2 = uVar2 + 1;
      *(_func_void_int **)this = param_1;
      this = this + 4;
    } while (uVar2 != uVar1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___acrt_has_user_matherr
// 
// Library: Visual Studio 2015 Release

bool ___acrt_has_user_matherr(void)

{
  byte bVar1;
  
  bVar1 = (byte)DAT_0041a208 & 0x1f;
  return (DAT_0041a208 ^ _DAT_0041b008) >> bVar1 != 0 ||
         (DAT_0041a208 ^ _DAT_0041b008) << 0x20 - bVar1 != 0;
}



void __cdecl FUN_0040b4e6(_func_void_int *param_1)

{
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b008,param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___acrt_invoke_user_matherr
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_invoke_user_matherr(undefined4 param_1)

{
  uint uVar1;
  byte bVar2;
  code *pcVar3;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  bVar2 = (byte)DAT_0041a208 & 0x1f;
  pcVar3 = (code *)((DAT_0041a208 ^ _DAT_0041b008) >> bVar2 |
                   (DAT_0041a208 ^ _DAT_0041b008) << 0x20 - bVar2);
  if (pcVar3 != (code *)0x0) {
    guard_check_icall();
    (*pcVar3)(param_1);
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___setusermatherr
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___setusermatherr(uint param_1)

{
  _DAT_0041b008 = __crt_fast_encode_pointer<>(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl common_configure_argv<char>(enum _crt_argv_mode)
// 
// Library: Visual Studio 2015 Release

int __cdecl common_configure_argv<char>(_crt_argv_mode param_1)

{
  int *piVar1;
  char **ppcVar2;
  char *pcVar3;
  char **ppcVar4;
  int iVar5;
  uint local_10;
  char **local_c;
  uint local_8;
  
  if ((param_1 == 2) || (param_1 == 1)) {
    ___acrt_initialize_multibyte();
    iVar5 = 0;
    (*(code *)0x19a4e)(0,&DAT_0041b010,0x104);
    _DAT_0041b2e0 = &DAT_0041b010;
    if ((DAT_0041b2d8 == (char *)0x0) || (pcVar3 = DAT_0041b2d8, *DAT_0041b2d8 == '\0')) {
      pcVar3 = &DAT_0041b010;
    }
    local_8 = 0;
    local_10 = 0;
    parse_command_line<char>(pcVar3,(char **)0x0,(char *)0x0,&local_8,&local_10);
    ppcVar2 = (char **)___acrt_allocate_buffer_for_argv(local_8,local_10,1);
    ppcVar4 = ppcVar2;
    if (ppcVar2 == (char **)0x0) {
      piVar1 = __errno();
      iVar5 = 0xc;
      *piVar1 = 0xc;
    }
    else {
      parse_command_line<char>(pcVar3,ppcVar2,(char *)(ppcVar2 + local_8),&local_8,&local_10);
      if (param_1 == 1) {
        _DAT_0041b2cc = local_8 - 1;
        ppcVar4 = (char **)0x0;
        DAT_0041b2d0 = ppcVar2;
      }
      else {
        local_c = (char **)0x0;
        iVar5 = FUN_0040e19e(ppcVar2,&local_c);
        ppcVar2 = local_c;
        if (iVar5 == 0) {
          _DAT_0041b2cc = 0;
          pcVar3 = *local_c;
          while (pcVar3 != (char *)0x0) {
            local_c = local_c + 1;
            _DAT_0041b2cc = _DAT_0041b2cc + 1;
            pcVar3 = *local_c;
          }
          local_c = (char **)0x0;
          iVar5 = 0;
          DAT_0041b2d0 = ppcVar2;
        }
        FID_conflict__free(local_c);
        local_c = (char **)0x0;
      }
    }
    FID_conflict__free(ppcVar4);
  }
  else {
    piVar1 = __errno();
    iVar5 = 0x16;
    *piVar1 = 0x16;
    FUN_0040c975();
  }
  return iVar5;
}



// Library Function - Single Match
//  void __cdecl parse_command_line<char>(char *,char * *,char *,unsigned int *,unsigned int *)
// 
// Library: Visual Studio 2015 Release

void __cdecl
parse_command_line<char>(char *param_1,char **param_2,char *param_3,uint *param_4,uint *param_5)

{
  bool bVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  bool bVar5;
  char *pcVar6;
  char *pcVar7;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (char **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  bVar5 = false;
  do {
    if (*param_1 == '\"') {
      bVar5 = !bVar5;
      cVar2 = '\"';
      pcVar6 = param_1 + 1;
    }
    else {
      *param_5 = *param_5 + 1;
      if (param_3 != (char *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      cVar2 = *param_1;
      pcVar6 = param_1 + 1;
      iVar4 = __ismbblead((int)cVar2);
      if (iVar4 != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (char *)0x0) {
          *param_3 = *pcVar6;
          param_3 = param_3 + 1;
        }
        pcVar6 = param_1 + 2;
      }
      if (cVar2 == '\0') {
        pcVar6 = pcVar6 + -1;
        goto LAB_0040b70c;
      }
    }
    param_1 = pcVar6;
  } while ((bVar5) || ((cVar2 != ' ' && (cVar2 != '\t'))));
  if (param_3 != (char *)0x0) {
    param_3[-1] = '\0';
  }
LAB_0040b70c:
  bVar5 = false;
  while (pcVar7 = pcVar6, *pcVar6 != '\0') {
    for (; (*pcVar7 == ' ' || (*pcVar7 == '\t')); pcVar7 = pcVar7 + 1) {
    }
    if (*pcVar7 == '\0') break;
    if (param_2 != (char **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar1 = true;
      uVar3 = 0;
      for (; *pcVar7 == '\\'; pcVar7 = pcVar7 + 1) {
        uVar3 = uVar3 + 1;
      }
      pcVar6 = pcVar7;
      if (*pcVar7 == '\"') {
        if (((uVar3 & 1) == 0) && ((!bVar5 || (pcVar6 = pcVar7 + 1, *pcVar6 != '\"')))) {
          bVar1 = false;
          bVar5 = !bVar5;
          pcVar6 = pcVar7;
        }
        uVar3 = uVar3 >> 1;
      }
      while (uVar3 != 0) {
        uVar3 = uVar3 - 1;
        if (param_3 != (char *)0x0) {
          *param_3 = '\\';
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      cVar2 = *pcVar6;
      if ((cVar2 == '\0') || ((!bVar5 && ((cVar2 == ' ' || (cVar2 == '\t')))))) break;
      if (bVar1) {
        if (param_3 != (char *)0x0) {
          *param_3 = cVar2;
          param_3 = param_3 + 1;
        }
        iVar4 = __ismbblead((int)*pcVar6);
        if (iVar4 != 0) {
          pcVar6 = pcVar6 + 1;
          *param_5 = *param_5 + 1;
          if (param_3 != (char *)0x0) {
            *param_3 = *pcVar6;
            param_3 = param_3 + 1;
          }
        }
        *param_5 = *param_5 + 1;
      }
      pcVar7 = pcVar6 + 1;
    }
    if (param_3 != (char *)0x0) {
      *param_3 = '\0';
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (char **)0x0) {
    *param_2 = (char *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// Library Function - Single Match
//  ___acrt_allocate_buffer_for_argv
// 
// Library: Visual Studio 2015 Release

int __cdecl ___acrt_allocate_buffer_for_argv(uint param_1,uint param_2,uint param_3)

{
  int iVar1;
  
  if ((param_1 < 0x3fffffff) && (param_2 < (uint)(0xffffffff / (ulonglong)param_3))) {
    if (param_2 * param_3 < param_1 * -4 - 1) {
      iVar1 = __calloc_base(param_2 * param_3 + param_1 * 4,1);
      FID_conflict__free((void *)0x0);
      return iVar1;
    }
  }
  return 0;
}



void __cdecl FUN_0040b846(_crt_argv_mode param_1)

{
  common_configure_argv<char>(param_1);
  return;
}



// Library Function - Single Match
//  int __cdecl common_initialize_environment_nolock<char>(void)
// 
// Library: Visual Studio 2015 Release

int __cdecl common_initialize_environment_nolock<char>(void)

{
  char *_Memory;
  char **ppcVar1;
  int iVar2;
  
  if (DAT_0041b118 != 0) {
    return 0;
  }
  ___acrt_initialize_multibyte();
  _Memory = (char *)___dcrt_get_narrow_environment_from_os();
  if (_Memory == (char *)0x0) {
    iVar2 = -1;
  }
  else {
    ppcVar1 = create_environment<char>(_Memory);
    if (ppcVar1 == (char **)0x0) {
      iVar2 = -1;
    }
    else {
      DAT_0041b124 = ppcVar1;
      __crt_state_management::dual_state_global<>::initialize
                ((dual_state_global<> *)&DAT_0041b118,(_func_void_int *)ppcVar1);
      iVar2 = 0;
    }
    FID_conflict__free((void *)0x0);
  }
  FID_conflict__free(_Memory);
  return iVar2;
}



// Library Function - Single Match
//  char * * __cdecl create_environment<char>(char * const)
// 
// Library: Visual Studio 2015 Release

char ** __cdecl create_environment<char>(char *param_1)

{
  char cVar1;
  char **ppcVar2;
  char *_Dst;
  errno_t eVar3;
  char *pcVar4;
  int iVar5;
  char **local_8;
  
  iVar5 = 0;
  cVar1 = *param_1;
  pcVar4 = param_1;
  while (cVar1 != '\0') {
    if (cVar1 != '=') {
      iVar5 = iVar5 + 1;
    }
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    cVar1 = *pcVar4;
  }
  ppcVar2 = (char **)__calloc_base(iVar5 + 1,4);
  local_8 = ppcVar2;
  if (ppcVar2 == (char **)0x0) {
LAB_0040b95b:
    ppcVar2 = (char **)0x0;
  }
  else {
    for (; *param_1 != '\0'; param_1 = param_1 + (int)pcVar4) {
      pcVar4 = param_1;
      do {
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      pcVar4 = pcVar4 + (1 - (int)(param_1 + 1));
      if (*param_1 != '=') {
        _Dst = (char *)__calloc_base((uint)pcVar4,1);
        if (_Dst == (char *)0x0) {
          free_environment<char>(ppcVar2);
          FID_conflict__free((void *)0x0);
          goto LAB_0040b95b;
        }
        eVar3 = _strcpy_s(_Dst,(rsize_t)pcVar4,param_1);
        if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
        *local_8 = _Dst;
        local_8 = local_8 + 1;
        FID_conflict__free((void *)0x0);
      }
    }
  }
  FID_conflict__free((void *)0x0);
  return ppcVar2;
}



// Library Function - Multiple Matches With Same Base Name
//  void __cdecl free_environment<char>(char * * const)
//  void __cdecl free_environment<wchar_t>(wchar_t * * const)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl free_environment<char>(char **param_1)

{
  char *_Memory;
  char **ppcVar1;
  
  if (param_1 != (char **)0x0) {
    _Memory = *param_1;
    ppcVar1 = param_1;
    while (_Memory != (char *)0x0) {
      FID_conflict__free(_Memory);
      ppcVar1 = ppcVar1 + 1;
      _Memory = *ppcVar1;
    }
    FID_conflict__free(param_1);
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall __crt_state_management::dual_state_global<char * *>::uninitialize<void
// (__cdecl&)(char * * &)>(void (__cdecl&)(char * * &))
//  public: void __thiscall __crt_state_management::dual_state_global<wchar_t *
// *>::uninitialize<void (__cdecl&)(wchar_t * * &)>(void (__cdecl&)(wchar_t * * &))
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void __thiscall uninitialize<>(void *this,undefined *param_1)

{
  void *pvVar1;
  uint uVar2;
  void *pvVar3;
  
  uVar2 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pvVar1 = (void *)((int)this + 4);
  for (; this != pvVar1; this = (void *)((int)this + 4)) {
    pvVar3 = this;
    guard_check_icall();
    (*(code *)param_1)(pvVar3);
  }
  __security_check_cookie(uVar2 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  void __cdecl uninitialize_environment_internal<char>(char * * &)
//  void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * * &)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl uninitialize_environment_internal<>(undefined4 *param_1)

{
  if ((char **)*param_1 != DAT_0041b124) {
    free_environment<char>((char **)*param_1);
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  void __cdecl uninitialize_environment_internal<char>(char * * &)
//  void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * * &)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl uninitialize_environment_internal<>(undefined4 *param_1)

{
  if ((char **)*param_1 != DAT_0041b120) {
    free_environment<char>((char **)*param_1);
  }
  return;
}



// Library Function - Single Match
//  ___dcrt_uninitialize_environments_nolock
// 
// Library: Visual Studio 2015 Release

void ___dcrt_uninitialize_environments_nolock(void)

{
  uninitialize<>(&DAT_0041b118,uninitialize_environment_internal<>);
  uninitialize<>(&DAT_0041b11c,uninitialize_environment_internal<>);
  free_environment<char>(DAT_0041b124);
  free_environment<char>(DAT_0041b120);
  return;
}



int __cdecl common_initialize_environment_nolock<char>(void)

{
  char *_Memory;
  char **ppcVar1;
  int iVar2;
  
  if (DAT_0041b118 != 0) {
    return 0;
  }
  ___acrt_initialize_multibyte();
  _Memory = (char *)___dcrt_get_narrow_environment_from_os();
  if (_Memory == (char *)0x0) {
    iVar2 = -1;
  }
  else {
    ppcVar1 = create_environment<char>(_Memory);
    if (ppcVar1 == (char **)0x0) {
      iVar2 = -1;
    }
    else {
      DAT_0041b124 = ppcVar1;
      __crt_state_management::dual_state_global<>::initialize
                ((dual_state_global<> *)&DAT_0041b118,(_func_void_int *)ppcVar1);
      iVar2 = 0;
    }
    FID_conflict__free((void *)0x0);
  }
  FID_conflict__free(_Memory);
  return iVar2;
}



// Library Function - Single Match
//  __get_narrow_winmain_command_line
// 
// Library: Visual Studio 2015 Release

char * __get_narrow_winmain_command_line(void)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  char *pcVar4;
  
  ___acrt_initialize_multibyte();
  pcVar4 = DAT_0041b2d8;
  if (DAT_0041b2d8 == (char *)0x0) {
    pcVar4 = &DAT_0041b128;
  }
  bVar2 = false;
  do {
    cVar1 = *pcVar4;
    if (cVar1 < '!') {
      if (cVar1 == '\0') {
        return pcVar4;
      }
      if (!bVar2) {
        for (; (*pcVar4 != '\0' && (*pcVar4 < '!')); pcVar4 = pcVar4 + 1) {
        }
        return pcVar4;
      }
    }
    if (cVar1 == '\"') {
      bVar2 = !bVar2;
    }
    iVar3 = __ismbblead((int)cVar1);
    if (iVar3 != 0) {
      pcVar4 = pcVar4 + 1;
    }
    pcVar4 = pcVar4 + 1;
  } while( true );
}



// Library Function - Single Match
//  __initterm
// 
// Library: Visual Studio 2015 Release

void __cdecl __initterm(undefined4 *param_1,undefined4 *param_2)

{
  code *pcVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar2 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  uVar4 = 0;
  uVar3 = ~-(uint)(param_2 < param_1) & (uint)((int)param_2 + (3 - (int)param_1)) >> 2;
  if (uVar3 != 0) {
    do {
      pcVar1 = (code *)*param_1;
      if (pcVar1 != (code *)0x0) {
        guard_check_icall();
        (*pcVar1)();
      }
      param_1 = param_1 + 1;
      uVar4 = uVar4 + 1;
    } while (uVar4 != uVar3);
  }
  __security_check_cookie(uVar2 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2015 Release

void __cdecl __initterm_e(undefined4 *param_1,undefined4 *param_2)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  for (; param_1 != param_2; param_1 = param_1 + 1) {
    pcVar1 = (code *)*param_1;
    if (pcVar1 != (code *)0x0) {
      guard_check_icall();
      iVar3 = (*pcVar1)();
      if (iVar3 != 0) break;
    }
  }
  __security_check_cookie(uVar2 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  int __cdecl atexit_exception_filter(unsigned long)
// 
// Library: Visual Studio 2015 Release

int __cdecl atexit_exception_filter(ulong param_1)

{
  return (uint)(param_1 == 0xe06d7363);
}



// WARNING: Function: __SEH_prolog4_GS replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl common_exit(int,enum _crt_exit_cleanup_mode,enum _crt_exit_return_mode)
// 
// Library: Visual Studio 2015 Release

void __cdecl common_exit(int param_1,_crt_exit_cleanup_mode param_2,_crt_exit_return_mode param_3)

{
  byte bVar1;
  byte bVar2;
  bool bVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 *local_18;
  
  if ((param_3 == 0) && (bVar3 = is_managed_app(), bVar3)) {
    try_cor_exit_process(param_1);
  }
  ___acrt_lock(2);
  if (DAT_0041b134 != '\0') goto LAB_0040bc3a;
  LOCK();
  DAT_0041b12c = 1;
  UNLOCK();
  if (param_2 == 0) {
    bVar2 = (byte)DAT_0041a208 & 0x1f;
    bVar1 = 0x20 - bVar2 & 0x1f;
    if (DAT_0041b130 != ((0U >> bVar1 | 0 << 0x20 - bVar1) ^ DAT_0041a208)) {
      uVar4 = DAT_0041a208 ^ DAT_0041b130;
      uVar7 = 0;
      uVar6 = 0;
      uVar5 = 0;
      guard_check_icall();
      (*(code *)(uVar4 >> bVar2 | uVar4 << 0x20 - bVar2))(uVar5,uVar6,uVar7);
    }
LAB_0040bbff:
    __execute_onexit_table();
  }
  else if (param_2 == 1) goto LAB_0040bbff;
  if (param_2 == 0) {
    __initterm((undefined4 *)&DAT_0041418c,(undefined4 *)&DAT_0041419c);
  }
  __initterm((undefined4 *)&DAT_004141a0,(undefined4 *)&DAT_004141a4);
  if (param_3 == 0) {
    DAT_0041b134 = '\x01';
  }
LAB_0040bc3a:
  FUN_0040bc6d();
  if (param_3 != 0) {
    FUN_00412f89();
    return;
  }
  exit_or_terminate_process(param_1);
  atexit_exception_filter(*(ulong *)*local_18);
  return;
}



void FUN_0040bc6d(void)

{
  ___acrt_unlock(2);
  return;
}



// Library Function - Single Match
//  void __cdecl exit_or_terminate_process(unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl exit_or_terminate_process(uint param_1)

{
  code *pcVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 in_ECX;
  
  cVar2 = ___acrt_is_packaged_app(in_ECX);
  if ((cVar2 != '\0') && ((*(uint *)((int)ProcessEnvironmentBlock + 0x68) >> 8 & 1) == 0)) {
    uVar3 = (*(code *)0x198f2)(param_1);
    (*(code *)0x19906)(uVar3);
  }
  try_cor_exit_process(param_1);
  (*(code *)0x19a90)(param_1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  bool __cdecl is_managed_app(void)
// 
// Library: Visual Studio 2015 Release

bool __cdecl is_managed_app(void)

{
  short *psVar1;
  int *piVar2;
  
  psVar1 = (short *)(*(code *)0x198de)(0);
  if ((((psVar1 != (short *)0x0) && (*psVar1 == 0x5a4d)) &&
      (piVar2 = (int *)(*(int *)(psVar1 + 0x1e) + (int)psVar1), *piVar2 == 0x4550)) &&
     (((short)piVar2[6] == 0x10b && (0xe < (uint)piVar2[0x1d])))) {
    return piVar2[0x3a] != 0;
  }
  return false;
}



// Library Function - Single Match
//  void __cdecl try_cor_exit_process(unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl try_cor_exit_process(uint param_1)

{
  int iVar1;
  code *pcVar2;
  int local_c;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  local_c = 0;
  iVar1 = (*(code *)0x19a9e)(0,L"mscoree.dll",&local_c);
  if ((iVar1 != 0) &&
     (pcVar2 = (code *)(*(code *)0x199ba)(local_c,"CorExitProcess"), pcVar2 != (code *)0x0)) {
    guard_check_icall();
    (*pcVar2)(param_1);
  }
  if (local_c != 0) {
    (*(code *)0x199ac)(local_c);
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_0040bd6b(undefined4 param_1)

{
  DAT_0041b130 = param_1;
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2015 Release

void __cdecl __cexit(void)

{
  common_exit(0,0,1);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2015 Release

void __cdecl __exit(int param_1)

{
  common_exit(param_1,2,0);
  return;
}



// WARNING: Function: __SEH_prolog4_GS replaced with injection: SEH_prolog4
// Library Function - Single Match
//  __register_thread_local_exe_atexit_callback
// 
// Library: Visual Studio 2015 Release

void __cdecl __register_thread_local_exe_atexit_callback(uint param_1)

{
  code *pcVar1;
  byte bVar2;
  __acrt_ptd *p_Var3;
  
  bVar2 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
  if (DAT_0041b130 == ((0U >> bVar2 | 0 << 0x20 - bVar2) ^ DAT_0041a208)) {
    DAT_0041b130 = __crt_fast_encode_pointer<>(param_1);
    return;
  }
  p_Var3 = ___acrt_getptd();
  pcVar1 = *(code **)(p_Var3 + 0xc);
  if (pcVar1 != (code *)0x0) {
    guard_check_icall();
    (*pcVar1)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2015 Release

void __cdecl _exit(int _Code)

{
  common_exit(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __set_fmode
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t __cdecl __set_fmode(int _Mode)

{
  int *piVar1;
  
  if (((_Mode != 0x4000) && (_Mode != 0x8000)) && (_Mode != 0x10000)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
    return 0x16;
  }
  LOCK();
  DAT_0041b3bc = _Mode;
  UNLOCK();
  return 0;
}



// Library Function - Single Match
//  ___acrt_set_locale_changed
// 
// Library: Visual Studio 2015 Release

undefined4 ___acrt_set_locale_changed(void)

{
  undefined4 uVar1;
  
  uVar1 = DAT_0041b138;
  LOCK();
  DAT_0041b138 = 1;
  UNLOCK();
  return uVar1;
}



void FUN_0040be8d(void)

{
  ___acrt_unlock(4);
  return;
}



// Library Function - Single Match
//  __configthreadlocale
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __configthreadlocale(int _Flag)

{
  uint uVar1;
  __acrt_ptd *p_Var2;
  int *piVar3;
  uint uVar4;
  
  p_Var2 = ___acrt_getptd();
  uVar1 = *(uint *)(p_Var2 + 0x350);
  if (_Flag == -1) {
    DAT_0041a970 = 0xffffffff;
  }
  else if (_Flag != 0) {
    if (_Flag == 1) {
      uVar4 = uVar1 | 2;
    }
    else {
      if (_Flag != 2) {
        piVar3 = __errno();
        *piVar3 = 0x16;
        FUN_0040c975();
        return -1;
      }
      uVar4 = uVar1 & 0xfffffffd;
    }
    *(uint *)(p_Var2 + 0x350) = uVar4;
  }
  return ((uVar1 & 2) == 0) + 1;
}



undefined4 FUN_0040bef8(void)

{
  return DAT_0041b13c;
}



// Library Function - Single Match
//  __set_new_mode
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl __set_new_mode(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  
  uVar1 = DAT_0041b13c;
  if ((param_1 != 0) && (param_1 != 1)) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_0040c975();
    return 0xffffffff;
  }
  LOCK();
  DAT_0041b13c = param_1;
  UNLOCK();
  return uVar1;
}



undefined * FUN_0040bf2d(void)

{
  return &DAT_0041b140;
}



void __cdecl FUN_0040bf33(_func_void_int *param_1)

{
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b144,param_1);
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2015 Release

int __cdecl __callnewh(size_t _Size)

{
  uint uVar1;
  code *pcVar2;
  int iVar3;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)__query_new_handler();
  if (pcVar2 != (code *)0x0) {
    guard_check_icall();
    iVar3 = (*pcVar2)(_Size);
    if (iVar3 != 0) {
      iVar3 = 1;
      goto LAB_0040bf7c;
    }
  }
  iVar3 = 0;
LAB_0040bf7c:
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __query_new_handler
// 
// Library: Visual Studio 2015 Release

uint __query_new_handler(void)

{
  byte bVar1;
  uint uVar2;
  
  ___acrt_lock(0);
  bVar1 = (byte)DAT_0041a208 & 0x1f;
  uVar2 = DAT_0041a208 ^ _DAT_0041b144;
  FUN_0040bfd4();
  return uVar2 >> bVar1 | uVar2 << 0x20 - bVar1;
}



void FUN_0040bfd4(void)

{
  ___acrt_unlock(0);
  return;
}



void __cdecl FUN_0040bfdd(size_t param_1)

{
  __malloc_base(param_1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_800076c951b434888f4765a74a194fcc>,class <lambda_4e60a939b0d047cfe11ddc22648dfba9> &,class
// <lambda_6dbb1268764f43b569ce7b67e331d33a> >(class <lambda_800076c951b434888f4765a74a194fcc>
// &&,class <lambda_4e60a939b0d047cfe11ddc22648dfba9> &,class
// <lambda_6dbb1268764f43b569ce7b67e331d33a> &&)
// 
// Library: Visual Studio 2015 Release

int __thiscall
__crt_seh_guarded_call<int>::operator()<>
          (__crt_seh_guarded_call<int> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int iVar1;
  
  ___acrt_lock(*(int *)param_1);
  iVar1 = <>::operator()(param_2);
  FUN_0040c02d();
  return iVar1;
}



void FUN_0040c02d(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_995298e7d72eb4c2aab26c0585b3abe5>,class <lambda_275893d493268fdec8709772e3fcec0e> &,class
// <lambda_293819299cbf9a7022e18b56a874bb5c> >(class <lambda_995298e7d72eb4c2aab26c0585b3abe5>
// &&,class <lambda_275893d493268fdec8709772e3fcec0e> &,class
// <lambda_293819299cbf9a7022e18b56a874bb5c> &&)
// 
// Library: Visual Studio 2015 Release

int __thiscall
__crt_seh_guarded_call<int>::operator()<>
          (__crt_seh_guarded_call<int> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int iVar1;
  
  ___acrt_lock(*(int *)param_1);
  iVar1 = <>::operator()(param_2);
  FUN_0040c07e();
  return iVar1;
}



void FUN_0040c07e(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  int __cdecl __acrt_lock_and_call<class <lambda_275893d493268fdec8709772e3fcec0e> >(enum
// __acrt_lock_id,class <lambda_275893d493268fdec8709772e3fcec0e> &&)
// 
// Library: Visual Studio 2015 Release

int __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  int iVar1;
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  __crt_seh_guarded_call<int> local_5;
  
  local_c = param_1;
  local_10 = param_1;
  iVar1 = __crt_seh_guarded_call<int>::operator()<>(&local_5,(<> *)&local_10,param_2,(<> *)&local_c)
  ;
  return iVar1;
}



// Library Function - Single Match
//  int __cdecl __acrt_lock_and_call<class <lambda_4e60a939b0d047cfe11ddc22648dfba9> >(enum
// __acrt_lock_id,class <lambda_4e60a939b0d047cfe11ddc22648dfba9> &&)
// 
// Library: Visual Studio 2015 Release

int __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  int iVar1;
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  __crt_seh_guarded_call<int> local_5;
  
  local_c = param_1;
  local_10 = param_1;
  iVar1 = __crt_seh_guarded_call<int>::operator()<>(&local_5,(<> *)&local_10,param_2,(<> *)&local_c)
  ;
  return iVar1;
}



// Library Function - Multiple Matches With Same Base Name
//  int (__cdecl*__cdecl __crt_fast_encode_pointer<int (__cdecl*)(void)>(int
// (__cdecl*const)(void)))(void)
//  void (__cdecl** __cdecl __crt_fast_encode_pointer<void (__cdecl**)(void)>(void (__cdecl**
// const)(void)))(void)
// 
// Library: Visual Studio 2015 Release

uint __cdecl __crt_fast_encode_pointer<>(uint param_1)

{
  byte bVar1;
  
  bVar1 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
  return (param_1 >> bVar1 | param_1 << 0x20 - bVar1) ^ DAT_0041a208;
}



// Library Function - Single Match
//  public: int __thiscall <lambda_275893d493268fdec8709772e3fcec0e>::operator()(void)const 
// 
// Library: Visual Studio 2015 Release

int __thiscall <>::operator()(<> *this)

{
  uint *puVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  sbyte sVar7;
  uint *puVar8;
  uint *puVar9;
  uint uVar10;
  uint *_Memory;
  uint local_18;
  
  uVar3 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  puVar8 = (uint *)**(int **)this;
  if (puVar8 == (uint *)0x0) {
    iVar4 = -1;
  }
  else {
    local_18 = DAT_0041a208 & 0x1f;
    sVar7 = (sbyte)local_18;
    _Memory = (uint *)((*puVar8 ^ DAT_0041a208) >> sVar7 | (*puVar8 ^ DAT_0041a208) << 0x20 - sVar7)
    ;
    puVar8 = (uint *)((puVar8[1] ^ DAT_0041a208) >> sVar7 |
                     (puVar8[1] ^ DAT_0041a208) << 0x20 - sVar7);
    if ((_Memory != (uint *)0x0) && (puVar9 = puVar8, _Memory != (uint *)0xffffffff)) {
      do {
        sVar7 = (sbyte)local_18;
        bVar2 = 0x20U - sVar7 & 0x1f;
        uVar5 = (0U >> bVar2 | 0 << 0x20 - bVar2) ^ DAT_0041a208;
        do {
          puVar8 = puVar8 + -1;
          if (puVar8 < _Memory) {
            if (_Memory != (uint *)0xffffffff) {
              FID_conflict__free(_Memory);
            }
            bVar2 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
            uVar5 = (0U >> bVar2 | 0 << 0x20 - bVar2) ^ DAT_0041a208;
            *(uint *)**(undefined4 **)this = uVar5;
            *(uint *)(**(int **)this + 4) = uVar5;
            *(uint *)(**(int **)this + 8) = uVar5;
            goto LAB_0040c206;
          }
        } while (*puVar8 == uVar5);
        uVar10 = *puVar8 ^ DAT_0041a208;
        *puVar8 = uVar5;
        guard_check_icall();
        (*(code *)(uVar10 >> sVar7 | uVar10 << 0x20 - sVar7))();
        local_18 = DAT_0041a208 & 0x1f;
        uVar10 = *(uint *)**(int **)this ^ DAT_0041a208;
        uVar5 = ((uint *)**(int **)this)[1] ^ DAT_0041a208;
        sVar7 = (sbyte)local_18;
        puVar1 = (uint *)(uVar10 >> sVar7 | uVar10 << 0x20 - sVar7);
        puVar6 = (uint *)(uVar5 >> sVar7 | uVar5 << 0x20 - sVar7);
        if ((puVar1 != _Memory) || (puVar6 != puVar9)) {
          puVar8 = puVar6;
          _Memory = puVar1;
          puVar9 = puVar6;
        }
      } while( true );
    }
LAB_0040c206:
    iVar4 = 0;
  }
  __security_check_cookie(uVar3 ^ (uint)&stack0xfffffffc);
  return iVar4;
}



// Library Function - Single Match
//  public: int __thiscall <lambda_4e60a939b0d047cfe11ddc22648dfba9>::operator()(void)const 
// 
// Library: Visual Studio 2015 Release

int __thiscall <>::operator()(<> *this)

{
  void *pvVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  uint *puVar5;
  void *pvVar6;
  uint *puVar7;
  uint uVar8;
  uint *puVar9;
  
  puVar5 = (uint *)**(int **)this;
  if (puVar5 == (uint *)0x0) {
    return -1;
  }
  bVar4 = (byte)DAT_0041a208 & 0x1f;
  puVar9 = (uint *)((puVar5[1] ^ DAT_0041a208) >> bVar4 | (puVar5[1] ^ DAT_0041a208) << 0x20 - bVar4
                   );
  puVar7 = (uint *)((puVar5[2] ^ DAT_0041a208) >> bVar4 | (puVar5[2] ^ DAT_0041a208) << 0x20 - bVar4
                   );
  pvVar6 = (void *)((*puVar5 ^ DAT_0041a208) >> bVar4 | (*puVar5 ^ DAT_0041a208) << 0x20 - bVar4);
  pvVar1 = pvVar6;
  if (puVar9 != puVar7) goto LAB_0040c313;
  uVar8 = (int)puVar7 - (int)pvVar6 >> 2;
  uVar2 = 0x200;
  if (uVar8 < 0x201) {
    uVar2 = uVar8;
  }
  uVar2 = uVar2 + uVar8;
  if (uVar2 == 0) {
    uVar2 = 0x20;
  }
  if (uVar2 < uVar8) {
LAB_0040c29a:
    uVar2 = uVar8 + 4;
    pvVar1 = (void *)FUN_0040fb85(pvVar6,uVar2,4);
    FID_conflict__free((void *)0x0);
    if (pvVar1 == (void *)0x0) {
      return -1;
    }
  }
  else {
    pvVar1 = (void *)FUN_0040fb85(pvVar6,uVar2,4);
    FID_conflict__free((void *)0x0);
    if (pvVar1 == (void *)0x0) goto LAB_0040c29a;
  }
  puVar9 = (uint *)((int)pvVar1 + uVar8 * 4);
  puVar7 = (uint *)((int)pvVar1 + uVar2 * 4);
  bVar4 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
  uVar2 = (0U >> bVar4 | 0 << 0x20 - bVar4) ^ DAT_0041a208;
  uVar8 = ~-(uint)(puVar7 < puVar9) & (uint)((int)puVar7 + (3 - (int)puVar9)) >> 2;
  if (uVar8 != 0) {
    uVar3 = 0;
    puVar5 = puVar9;
    do {
      uVar3 = uVar3 + 1;
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
    } while (uVar3 != uVar8);
  }
LAB_0040c313:
  uVar2 = __crt_fast_encode_pointer<>(**(uint **)(this + 4));
  *puVar9 = uVar2;
  pvVar1 = __crt_fast_encode_pointer<void*>(pvVar1);
  *(void **)**(undefined4 **)this = pvVar1;
  pvVar1 = __crt_fast_encode_pointer<void*>(puVar9 + 1);
  *(void **)(**(int **)this + 4) = pvVar1;
  pvVar1 = __crt_fast_encode_pointer<void*>(puVar7);
  *(void **)(**(int **)this + 8) = pvVar1;
  return 0;
}



// Library Function - Single Match
//  __crt_atexit
// 
// Library: Visual Studio 2015 Release

void __crt_atexit(void)

{
  __register_onexit_function();
  return;
}



// Library Function - Single Match
//  __execute_onexit_table
// 
// Library: Visual Studio 2015 Release

void __execute_onexit_table(void)

{
  undefined1 *local_8;
  
  local_8 = &stack0x00000004;
  __acrt_lock_and_call<>(2,(<> *)&local_8);
  return;
}



// Library Function - Single Match
//  __initialize_onexit_table
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl __initialize_onexit_table(uint *param_1)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  
  if (param_1 == (uint *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    if (*param_1 == param_1[2]) {
      bVar1 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
      uVar3 = (0U >> bVar1 | 0 << 0x20 - bVar1) ^ DAT_0041a208;
      *param_1 = uVar3;
      param_1[1] = uVar3;
      param_1[2] = uVar3;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// Library Function - Single Match
//  __register_onexit_function
// 
// Library: Visual Studio 2015 Release

void __register_onexit_function(void)

{
  undefined1 *local_c;
  undefined1 *local_8;
  
  local_c = &stack0x00000004;
  local_8 = &stack0x00000008;
  __acrt_lock_and_call<>(2,(<> *)&local_c);
  return;
}



undefined1 FUN_0040c41a(void)

{
  return 1;
}



// Library Function - Single Match
//  ___acrt_initialize
// 
// Library: Visual Studio 2015 Release

void ___acrt_initialize(void)

{
  ___acrt_execute_initializers(&PTR_LAB_00414ce8,&DAT_00414d60);
  return;
}



// Library Function - Single Match
//  ___acrt_uninitialize
// 
// Library: Visual Studio 2015 Release

void ___acrt_uninitialize(void)

{
  ___acrt_execute_uninitializers(&PTR_LAB_00414ce8,&DAT_00414d60);
  return;
}



// Library Function - Single Match
//  __controlfp_s
// 
// Library: Visual Studio 2015 Release

errno_t __cdecl __controlfp_s(uint *_CurrentState,uint _NewValue,uint _Mask)

{
  int *piVar1;
  errno_t eVar2;
  uint uVar3;
  
  uVar3 = _Mask & 0xfff7ffff;
  if ((_NewValue & uVar3 & 0xfcf0fce0) == 0) {
    if (_CurrentState == (uint *)0x0) {
      __control87(_NewValue,uVar3);
    }
    else {
      uVar3 = __control87(_NewValue,uVar3);
      *_CurrentState = uVar3;
    }
    eVar2 = 0;
  }
  else {
    if (_CurrentState != (uint *)0x0) {
      uVar3 = __control87(0,0);
      *_CurrentState = uVar3;
    }
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_0040c975();
  }
  return eVar2;
}



// WARNING: Function: __SEH_prolog4_GS replaced with injection: SEH_prolog4
// Library Function - Single Match
//  _terminate
// 
// Library: Visual Studio 2015 Release

void __cdecl terminate(void)

{
  code *pcVar1;
  __acrt_ptd *p_Var2;
  
  p_Var2 = ___acrt_getptd();
  pcVar1 = *(code **)(p_Var2 + 0xc);
  if (pcVar1 != (code *)0x0) {
    guard_check_icall();
    (*pcVar1)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



void __cdecl FID_conflict__free(void *_Memory)

{
  int iVar1;
  int *piVar2;
  ulong uVar3;
  
  if (_Memory != (void *)0x0) {
    iVar1 = (*(code *)0x19abe)(DAT_0041b5d0,0,_Memory);
    if (iVar1 == 0) {
      piVar2 = __errno();
      uVar3 = (*(code *)0x1991a)();
      iVar1 = FID_conflict____acrt_errno_from_os_error(uVar3);
      *piVar2 = iVar1;
    }
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __free_base
//  _free
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict__free(void *_Memory)

{
  int iVar1;
  int *piVar2;
  ulong uVar3;
  
  if (_Memory != (void *)0x0) {
    iVar1 = (*(code *)0x19abe)(DAT_0041b5d0,0,_Memory);
    if (iVar1 == 0) {
      piVar2 = __errno();
      uVar3 = (*(code *)0x1991a)();
      iVar1 = FID_conflict____acrt_errno_from_os_error(uVar3);
      *piVar2 = iVar1;
    }
  }
  return;
}



// Library Function - Single Match
//  __malloc_base
// 
// Library: Visual Studio 2015 Release

int __cdecl __malloc_base(size_t param_1)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      iVar1 = (*(code *)0x19aca)(DAT_0041b5d0,0,param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
      iVar1 = FUN_0040bef8();
    } while ((iVar1 != 0) && (iVar1 = __callnewh(param_1), iVar1 != 0));
  }
  piVar2 = __errno();
  *piVar2 = 0xc;
  return 0;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  int iVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      pcVar3 = _Dst;
      do {
        cVar1 = pcVar3[(int)_Src - (int)_Dst];
        *pcVar3 = cVar1;
        pcVar3 = pcVar3 + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      piVar2 = __errno();
      iVar4 = 0x22;
      goto LAB_0040c653;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  iVar4 = 0x16;
LAB_0040c653:
  *piVar2 = iVar4;
  FUN_0040c975();
  return iVar4;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2015 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  
  iVar2 = ___acrt_get_sigabrt_handler();
  if (iVar2 != 0) {
    _raise(0x16);
  }
  if ((DAT_0041a270 & 2) != 0) {
    iVar2 = FUN_00412d36();
    if (iVar2 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
    }
    ___acrt_call_reportfault(3,0x40000015,1);
  }
                    // WARNING: Subroutine does not return
  __exit(3);
}



// Library Function - Single Match
//  __calloc_base
// 
// Library: Visual Studio 2015 Release

int __cdecl __calloc_base(uint param_1,uint param_2)

{
  int iVar1;
  int *piVar2;
  size_t _Size;
  
  if ((param_1 == 0) || (param_2 <= 0xffffffe0 / param_1)) {
    _Size = param_1 * param_2;
    if (_Size == 0) {
      _Size = 1;
    }
    do {
      iVar1 = (*(code *)0x19aca)(DAT_0041b5d0,8,_Size);
      if (iVar1 != 0) {
        return iVar1;
      }
      iVar1 = FUN_0040bef8();
    } while ((iVar1 != 0) && (iVar1 = __callnewh(_Size), iVar1 != 0));
  }
  piVar2 = __errno();
  *piVar2 = 0xc;
  return 0;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct __crt_locale_pointers * const)
// 
// Library: Visual Studio 2015 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,__crt_locale_pointers *param_1)

{
  uint uVar1;
  undefined *puVar2;
  __acrt_ptd *p_Var3;
  
  this[0xc] = (_LocaleUpdate)0x0;
  if (param_1 == (__crt_locale_pointers *)0x0) {
    if (DAT_0041b138 != 0) {
      p_Var3 = ___acrt_getptd();
      *(__acrt_ptd **)this = p_Var3;
      *(int *)(this + 4) = *(int *)(p_Var3 + 0x4c);
      *(int *)(this + 8) = *(int *)(p_Var3 + 0x48);
      ___acrt_update_locale_info((int)p_Var3,(int *)(this + 4));
      ___acrt_update_multibyte_info(*(int *)this,(int *)(this + 8));
      uVar1 = *(uint *)(*(int *)this + 0x350);
      if ((uVar1 & 2) != 0) {
        return this;
      }
      *(uint *)(*(int *)this + 0x350) = uVar1 | 2;
      this[0xc] = (_LocaleUpdate)0x1;
      return this;
    }
    *(undefined **)(this + 4) = PTR_PTR_DAT_0041a908;
    puVar2 = PTR_DAT_0041a90c;
  }
  else {
    *(undefined4 *)(this + 4) = *(undefined4 *)param_1;
    puVar2 = *(undefined **)(param_1 + 4);
  }
  *(undefined **)(this + 8) = puVar2;
  return this;
}



// Library Function - Single Match
//  ___acrt_call_reportfault
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_call_reportfault(int param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_324;
  undefined4 local_320;
  undefined4 local_2d4 [39];
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  if (param_1 != -1) {
    FUN_00409e68();
  }
  _memset(&local_324,0,0x50);
  _memset(local_2d4,0,0x2cc);
  local_2d4[0] = 0x10001;
  local_324 = param_2;
  local_320 = param_3;
  iVar2 = (*(code *)0x19862)();
  (*(code *)0x19892)();
  iVar3 = (*(code *)0x19876)();
  if (((iVar3 == 0) && (iVar2 == 0)) && (param_1 != -1)) {
    FUN_00409e68();
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_0040c8e6(_func_void_int *param_1)

{
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b160,param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __invalid_parameter
// 
// Library: Visual Studio 2015 Release

void __cdecl
__invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                   uintptr_t param_5)

{
  uint uVar1;
  __acrt_ptd *p_Var2;
  byte bVar3;
  code *pcVar4;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  p_Var2 = ___acrt_getptd_noexit();
  if (((p_Var2 == (__acrt_ptd *)0x0) || (pcVar4 = *(code **)(p_Var2 + 0x35c), pcVar4 == (code *)0x0)
      ) && (bVar3 = (byte)DAT_0041a208 & 0x1f,
           pcVar4 = (code *)((DAT_0041a208 ^ _DAT_0041b160) >> bVar3 |
                            (DAT_0041a208 ^ _DAT_0041b160) << 0x20 - bVar3), pcVar4 == (code *)0x0))
  {
                    // WARNING: Subroutine does not return
    __invoke_watson(param_1,param_2,param_3,param_4,param_5);
  }
  guard_check_icall();
  (*pcVar4)(param_1,param_2,param_3,param_4,param_5);
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040c975(void)

{
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2015 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  code *pcVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = FUN_00412d36();
  if (iVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  ___acrt_call_reportfault(2,0xc0000417,1);
  uVar3 = (*(code *)0x198f2)(0xc0000417);
  (*(code *)0x19906)(uVar3);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_errno_from_os_error
//  __get_errno_from_oserr
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

int __cdecl FID_conflict____acrt_errno_from_os_error(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00414d60)[uVar1 * 2]) {
      return (&DAT_00414d64)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



// Library Function - Single Match
//  ___acrt_errno_map_os_error
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_errno_map_os_error(ulong param_1)

{
  ulong *puVar1;
  int iVar2;
  int *piVar3;
  
  puVar1 = ___doserrno();
  *puVar1 = param_1;
  iVar2 = FID_conflict____acrt_errno_from_os_error(param_1);
  piVar3 = __errno();
  *piVar3 = iVar2;
  return;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2015 Release

ulong * __cdecl ___doserrno(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = ___acrt_getptd_noexit();
  if (p_Var1 == (__acrt_ptd *)0x0) {
    return (ulong *)&DAT_0041a278;
  }
  return (ulong *)(p_Var1 + 0x14);
}



// Library Function - Single Match
//  __errno
// 
// Library: Visual Studio 2015 Release

int * __cdecl __errno(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = ___acrt_getptd_noexit();
  if (p_Var1 == (__acrt_ptd *)0x0) {
    return (int *)&DAT_0041a274;
  }
  return (int *)(p_Var1 + 0x10);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_123407a5e2ac06da108355a851863b7a>,class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> &,class
// <lambda_ae55bdf541ad94d75914d381c370e64d> >(class <lambda_123407a5e2ac06da108355a851863b7a>
// &&,class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> &,class
// <lambda_ae55bdf541ad94d75914d381c370e64d> &&)
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_218ce3db14220d0be481dae8ef3383b6>,class <lambda_628dfdc04ba53c8bfc02c9951375f3f5> &,class
// <lambda_57dc472bd5c9d5f3b2cbca59b8a843ae> >(class <lambda_218ce3db14220d0be481dae8ef3383b6>
// &&,class <lambda_628dfdc04ba53c8bfc02c9951375f3f5> &,class
// <lambda_57dc472bd5c9d5f3b2cbca59b8a843ae> &&)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

int operator()<>(uint *param_1,undefined4 *param_2)

{
  uint _FileHandle;
  int iVar1;
  int *piVar2;
  
  ___acrt_lowio_lock_fh(*param_1);
  _FileHandle = *(uint *)*param_2;
  if ((*(byte *)((&DAT_0041b3c0)[(int)_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3f) * 0x30) & 1)
      == 0) {
    piVar2 = __errno();
    *piVar2 = 9;
    iVar1 = -1;
  }
  else {
    iVar1 = __close_nolock(_FileHandle);
  }
  FUN_0040caba();
  return iVar1;
}



void FUN_0040caba(void)

{
  int unaff_EBP;
  
  ___acrt_lowio_unlock_fh(**(uint **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  int __cdecl __acrt_lowio_lock_fh_and_call<class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>
// >(int,class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec> &&)
// 
// Library: Visual Studio 2015 Release

int __cdecl __acrt_lowio_lock_fh_and_call<>(int param_1,<> *param_2)

{
  int iVar1;
  uint local_10;
  int local_c;
  
  local_c = param_1;
  local_10 = param_1;
  iVar1 = operator()<>(&local_10,(undefined4 *)param_2);
  return iVar1;
}



// Library Function - Single Match
//  __close
// 
// Library: Visual Studio 2015 Release

int __cdecl __close(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int *local_8;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b5c0)) &&
       ((*(byte *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3fU) * 0x30) & 1) !=
        0)) {
      local_8 = &_FileHandle;
      iVar3 = __acrt_lowio_lock_fh_and_call<>(_FileHandle,(<> *)&local_8);
      return iVar3;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c975();
  }
  return -1;
}



// Library Function - Single Match
//  __close_nolock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

int __cdecl __close_nolock(int _FileHandle)

{
  intptr_t iVar1;
  intptr_t iVar2;
  int iVar3;
  ulong uVar4;
  
  iVar1 = __get_osfhandle(_FileHandle);
  if (iVar1 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_0041b3c0 + 0x88) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_0041b3c0 + 0x58) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_0040cb83;
    }
    iVar1 = __get_osfhandle(_FileHandle);
    iVar3 = (*(code *)0x19ad6)(iVar1);
    if (iVar3 == 0) {
      uVar4 = (*(code *)0x1991a)();
      goto LAB_0040cbd5;
    }
  }
LAB_0040cb83:
  uVar4 = 0;
LAB_0040cbd5:
  __free_osfhnd(_FileHandle);
  *(undefined1 *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3fU) * 0x30) = 0;
  if (uVar4 == 0) {
    iVar3 = 0;
  }
  else {
    ___acrt_errno_map_os_error(uVar4);
    iVar3 = -1;
  }
  return iVar3;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2015 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
    return -1;
  }
  return _File->_file;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2015 Release

void __cdecl __lock_file(FILE *_File)

{
  (*(code *)0x199fa)(_File + 1);
  return;
}



void __cdecl FUN_0040cd57(int param_1)

{
  (*(code *)0x19a12)(param_1 + 0x20);
  return;
}



// Library Function - Single Match
//  void __cdecl __acrt_stdio_free_stream(class __crt_stdio_stream)
// 
// Library: Visual Studio 2015 Release

void __cdecl __acrt_stdio_free_stream(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[4] = 0xffffffff;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  LOCK();
  param_1[3] = 0;
  UNLOCK();
  return;
}



// Library Function - Single Match
//  ___acrt_stdio_free_buffer_nolock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_stdio_free_buffer_nolock(undefined4 *param_1)

{
  uint *puVar1;
  
  puVar1 = param_1 + 3;
  if (((*puVar1 >> 0xd & 1) != 0) && ((*puVar1 >> 6 & 1) != 0)) {
    FID_conflict__free((void *)param_1[1]);
    LOCK();
    *puVar1 = *puVar1 & 0xfffffebf;
    UNLOCK();
    param_1[1] = 0;
    *param_1 = 0;
    param_1[2] = 0;
  }
  return;
}



// Library Function - Single Match
//  ___acrt_lock
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_lock(int param_1)

{
  (*(code *)0x199fa)(&DAT_0041b170 + param_1 * 0x18);
  return;
}



undefined4 FUN_0040ce3c(void)

{
  undefined4 in_EAX;
  int iVar1;
  undefined *puVar2;
  
  if (DAT_0041b2a8 != 0) {
    puVar2 = &DAT_0041b158 + DAT_0041b2a8 * 0x18;
    iVar1 = DAT_0041b2a8;
    do {
      in_EAX = (*(code *)0x19a2a)(puVar2);
      DAT_0041b2a8 = DAT_0041b2a8 + -1;
      puVar2 = puVar2 + -0x18;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// Library Function - Single Match
//  ___acrt_unlock
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_unlock(int param_1)

{
  (*(code *)0x19a12)(&DAT_0041b170 + param_1 * 0x18);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_61cee617f5178ae960314fd4d05640a0>,class <lambda_6978c1fb23f02e42e1d9e99668cc68aa> &,class
// <lambda_9cd88cf8ad10232537feb2133f08c833> >(class <lambda_61cee617f5178ae960314fd4d05640a0>
// &&,class <lambda_6978c1fb23f02e42e1d9e99668cc68aa> &,class
// <lambda_9cd88cf8ad10232537feb2133f08c833> &&)
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_9e9de3de5fa147e2223d7db92bc10aa6>,class <lambda_38ce7e780aa69e748d6df282ebc68efe> &,class
// <lambda_8ca6da459f0f6780f1cff60fdc3d00e5> >(class <lambda_9e9de3de5fa147e2223d7db92bc10aa6>
// &&,class <lambda_38ce7e780aa69e748d6df282ebc68efe> &,class
// <lambda_8ca6da459f0f6780f1cff60fdc3d00e5> &&)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

undefined4 operator()<>(uint *param_1,undefined4 *param_2)

{
  uint _FileHandle;
  intptr_t iVar1;
  int iVar2;
  ulong *puVar3;
  ulong uVar4;
  int *piVar5;
  undefined4 uVar6;
  
  uVar6 = 0;
  ___acrt_lowio_lock_fh(*param_1);
  _FileHandle = *(uint *)*param_2;
  if ((*(byte *)((&DAT_0041b3c0)[(int)_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3f) * 0x30) & 1)
      != 0) {
    iVar1 = __get_osfhandle(_FileHandle);
    iVar2 = (*(code *)0x19ae4)(iVar1);
    if (iVar2 != 0) goto LAB_0040cef4;
    puVar3 = ___doserrno();
    uVar4 = (*(code *)0x1991a)();
    *puVar3 = uVar4;
  }
  piVar5 = __errno();
  *piVar5 = 9;
  uVar6 = 0xffffffff;
LAB_0040cef4:
  FUN_0040cf10();
  return uVar6;
}



void FUN_0040cf10(void)

{
  int unaff_EBP;
  
  ___acrt_lowio_unlock_fh(**(uint **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  int __cdecl __acrt_lowio_lock_fh_and_call<class <lambda_6978c1fb23f02e42e1d9e99668cc68aa>
// >(int,class <lambda_6978c1fb23f02e42e1d9e99668cc68aa> &&)
// 
// Library: Visual Studio 2015 Release

int __cdecl __acrt_lowio_lock_fh_and_call<>(int param_1,<> *param_2)

{
  int iVar1;
  uint local_10;
  int local_c;
  
  local_c = param_1;
  local_10 = param_1;
  iVar1 = operator()<>(&local_10,(undefined4 *)param_2);
  return iVar1;
}



// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2015 Release

int __cdecl __commit(int _FileHandle)

{
  int *piVar1;
  int iVar2;
  int *local_8;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b5c0)) &&
       ((*(byte *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3fU) * 0x30) & 1) !=
        0)) {
      local_8 = &_FileHandle;
      iVar2 = __acrt_lowio_lock_fh_and_call<>(_FileHandle,(<> *)&local_8);
      return iVar2;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_0040c975();
  }
  return -1;
}



// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_double_translated_ansi_nolock(int,char
// const * const,unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl write_double_translated_ansi_nolock(int param_1,char *param_2,uint param_3)

{
  byte bVar1;
  byte *pbVar2;
  undefined4 uVar3;
  ushort *puVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  byte *pbVar10;
  int in_stack_00000010;
  byte *_SrcCh;
  size_t _SrcSizeInBytes;
  uint local_24;
  undefined2 local_20;
  wchar_t local_1c [2];
  undefined1 local_18 [8];
  byte local_10;
  undefined1 local_f;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  iVar8 = (int)param_2 >> 6;
  iVar9 = ((uint)param_2 & 0x3f) * 0x30;
  uVar7 = *(undefined4 *)((&DAT_0041b3c0)[iVar8] + 0x18 + iVar9);
  pbVar2 = (byte *)(in_stack_00000010 + param_3);
  uVar3 = (*(code *)0x19af8)();
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  pbVar10 = (byte *)param_3;
  if (param_3 < pbVar2) {
    do {
      local_1c[0] = L'\0';
      local_20 = CONCAT11(*pbVar10,(undefined1)local_20);
      iVar5 = (&DAT_0041b3c0)[iVar8];
      bVar1 = *(byte *)(iVar5 + 0x2d + iVar9);
      if ((bVar1 & 4) == 0) {
        puVar4 = ___pctype_func();
        if ((puVar4[*pbVar10] & 0x8000) == 0) {
          _SrcSizeInBytes = 1;
          _SrcCh = pbVar10;
          goto LAB_0040d087;
        }
        if (pbVar2 <= pbVar10) {
          *(byte *)((&DAT_0041b3c0)[iVar8] + 0x2e + iVar9) = *pbVar10;
          pbVar10 = (byte *)((&DAT_0041b3c0)[iVar8] + 0x2d + iVar9);
          *pbVar10 = *pbVar10 | 4;
          *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
          break;
        }
        iVar5 = _mbtowc(local_1c,(char *)pbVar10,2);
        if (iVar5 == -1) break;
        pbVar10 = pbVar10 + 1;
      }
      else {
        local_10 = *(byte *)(iVar5 + 0x2e + iVar9);
        uVar6 = CONCAT11(*pbVar10,bVar1) & 0xfffffffb;
        _SrcSizeInBytes = 2;
        local_f = (undefined1)(uVar6 >> 8);
        *(char *)(iVar5 + 0x2d + iVar9) = (char)uVar6;
        _SrcCh = &local_10;
LAB_0040d087:
        iVar5 = _mbtowc(local_1c,(char *)_SrcCh,_SrcSizeInBytes);
        if (iVar5 == -1) break;
      }
      pbVar10 = pbVar10 + 1;
      uVar6 = (*(code *)0x19a7a)(uVar3,0,local_1c,1,local_18,5,0,0);
      if (uVar6 == 0) break;
      iVar5 = (*(code *)0x19a42)(uVar7,local_18,uVar6,&local_24,0);
      if (iVar5 == 0) {
LAB_0040d14b:
        uVar7 = (*(code *)0x1991a)();
        *(undefined4 *)param_1 = uVar7;
        break;
      }
      *(byte **)(param_1 + 4) = pbVar10 + (*(int *)(param_1 + 8) - param_3);
      if (local_24 < uVar6) break;
      if (local_20._1_1_ == '\n') {
        local_20 = 0xd;
        iVar5 = (*(code *)0x19a42)(uVar7,&local_20,1,&local_24,0);
        if (iVar5 == 0) goto LAB_0040d14b;
        if (local_24 == 0) break;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
      }
    } while (pbVar10 < pbVar2);
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_double_translated_unicode_nolock(char
// const * const,unsigned int)
// 
// Library: Visual Studio 2015 Release

char * __cdecl write_double_translated_unicode_nolock(char *param_1,uint param_2)

{
  wchar_t _WCh;
  wchar_t wVar1;
  wint_t wVar2;
  wchar_t *pwVar3;
  undefined4 uVar4;
  int in_stack_0000000c;
  
  param_1[0] = '\0';
  param_1[1] = '\0';
  param_1[2] = '\0';
  param_1[3] = '\0';
  param_1[4] = '\0';
  param_1[5] = '\0';
  param_1[6] = '\0';
  param_1[7] = '\0';
  param_1[8] = '\0';
  param_1[9] = '\0';
  param_1[10] = '\0';
  param_1[0xb] = '\0';
  pwVar3 = (wchar_t *)(in_stack_0000000c + param_2);
  if (param_2 < pwVar3) {
    do {
      _WCh = *(wchar_t *)param_2;
      wVar1 = __putwch_nolock(_WCh);
      if (wVar1 != _WCh) {
LAB_0040d1c2:
        uVar4 = (*(code *)0x1991a)();
        *(undefined4 *)param_1 = uVar4;
        return param_1;
      }
      *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 2;
      if (_WCh == L'\n') {
        wVar2 = __putwch_nolock(L'\r');
        if (wVar2 != 0xd) goto LAB_0040d1c2;
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      param_2 = param_2 + 2;
    } while (param_2 < pwVar3);
  }
  return param_1;
}



// Library Function - Single Match
//  bool __cdecl write_requires_double_translation_nolock(int)
// 
// Library: Visual Studio 2015 Release

bool __cdecl write_requires_double_translation_nolock(int param_1)

{
  int iVar1;
  __acrt_ptd *p_Var2;
  int iVar3;
  bool bVar4;
  undefined1 local_8 [4];
  
  iVar1 = __isatty(param_1);
  if (iVar1 == 0) {
    bVar4 = false;
  }
  else {
    iVar3 = param_1 >> 6;
    iVar1 = (param_1 & 0x3fU) * 0x30;
    if (((*(byte *)((&DAT_0041b3c0)[iVar3] + 0x28 + iVar1) & 0x80) == 0) ||
       ((p_Var2 = ___acrt_getptd(), *(int *)(*(int *)(p_Var2 + 0x4c) + 0xa8) == 0 &&
        (*(char *)((&DAT_0041b3c0)[iVar3] + 0x29 + iVar1) == '\0')))) {
      bVar4 = false;
    }
    else {
      iVar1 = (*(code *)0x19b08)(*(undefined4 *)((&DAT_0041b3c0)[iVar3] + 0x18 + iVar1),local_8);
      bVar4 = iVar1 != 0;
    }
  }
  return bVar4;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_text_ansi_nolock(int,char const *
// const,unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl write_text_ansi_nolock(int param_1,char *param_2,uint param_3)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  char *pcVar4;
  int in_stack_00000010;
  uint local_1410;
  char *local_140c;
  char local_1408 [5120];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  uVar3 = *(undefined4 *)((&DAT_0041b3c0)[(int)param_2 >> 6] + 0x18 + ((uint)param_2 & 0x3f) * 0x30)
  ;
  *(undefined4 *)param_1 = 0;
  local_140c = (char *)(in_stack_00000010 + param_3);
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  do {
    if (local_140c <= param_3) break;
    pcVar4 = local_1408;
    do {
      if (local_140c <= param_3) break;
      cVar1 = *(char *)param_3;
      param_3 = param_3 + 1;
      if (cVar1 == '\n') {
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
        *pcVar4 = '\r';
        pcVar4 = pcVar4 + 1;
      }
      *pcVar4 = cVar1;
      pcVar4 = pcVar4 + 1;
    } while (pcVar4 < local_1408 + 0x13ff);
    iVar2 = (*(code *)0x19a42)(uVar3,local_1408,(int)pcVar4 - (int)local_1408,&local_1410,0);
    if (iVar2 == 0) {
      uVar3 = (*(code *)0x1991a)();
      *(undefined4 *)param_1 = uVar3;
      break;
    }
    *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + local_1410;
  } while ((uint)((int)pcVar4 - (int)local_1408) <= local_1410);
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_text_utf16le_nolock(int,char const *
// const,unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl write_text_utf16le_nolock(int param_1,char *param_2,uint param_3)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  short *psVar4;
  int in_stack_00000010;
  uint local_1410;
  short *local_140c;
  short local_1408 [2560];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  uVar3 = *(undefined4 *)((&DAT_0041b3c0)[(int)param_2 >> 6] + 0x18 + ((uint)param_2 & 0x3f) * 0x30)
  ;
  local_140c = (short *)(in_stack_00000010 + param_3);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  do {
    if (local_140c <= param_3) break;
    psVar4 = local_1408;
    do {
      if (local_140c <= param_3) break;
      sVar1 = *(short *)param_3;
      param_3 = param_3 + 2;
      if (sVar1 == 10) {
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 2;
        *psVar4 = 0xd;
        psVar4 = psVar4 + 1;
      }
      *psVar4 = sVar1;
      psVar4 = psVar4 + 1;
    } while (psVar4 < local_1408 + 0x9ff);
    iVar2 = (*(code *)0x19a42)(uVar3,local_1408,(int)psVar4 - (int)local_1408,&local_1410,0);
    if (iVar2 == 0) {
      uVar3 = (*(code *)0x1991a)();
      *(undefined4 *)param_1 = uVar3;
      break;
    }
    *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + local_1410;
  } while ((uint)((int)psVar4 - (int)local_1408) <= local_1410);
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_text_utf8_nolock(int,char const *
// const,unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl write_text_utf8_nolock(int param_1,char *param_2,uint param_3)

{
  short sVar1;
  short *psVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  short *psVar7;
  int in_stack_00000010;
  int local_1414;
  short *local_1410;
  undefined1 local_140c [3416];
  short local_6b4 [854];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  uVar5 = *(undefined4 *)((&DAT_0041b3c0)[(int)param_2 >> 6] + 0x18 + ((uint)param_2 & 0x3f) * 0x30)
  ;
  local_1410 = (short *)(in_stack_00000010 + param_3);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  psVar7 = (short *)param_3;
  if (param_3 < local_1410) {
    do {
      uVar6 = 0;
      psVar2 = local_6b4;
      do {
        if (local_1410 <= psVar7) break;
        sVar1 = *psVar7;
        psVar7 = psVar7 + 1;
        if (sVar1 == 10) {
          *psVar2 = 0xd;
          psVar2 = psVar2 + 1;
        }
        *psVar2 = sVar1;
        psVar2 = psVar2 + 1;
      } while (psVar2 < local_6b4 + 0x354);
      uVar3 = (*(code *)0x19a7a)(0xfde9,0,local_6b4,(int)psVar2 - (int)local_6b4 >> 1,local_140c,
                                 0xd55,0,0);
      if (uVar3 == 0) {
LAB_0040d528:
        uVar5 = (*(code *)0x1991a)();
        *(undefined4 *)param_1 = uVar5;
        break;
      }
      do {
        iVar4 = (*(code *)0x19a42)(uVar5,local_140c + uVar6,uVar3 - uVar6,&local_1414,0);
        if (iVar4 == 0) goto LAB_0040d528;
        uVar6 = uVar6 + local_1414;
      } while (uVar6 < uVar3);
      *(uint *)(param_1 + 4) = (int)psVar7 - param_3;
    } while (psVar7 < local_1410);
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2015 Release

int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b5c0)) {
      iVar3 = (_FileHandle & 0x3fU) * 0x30;
      if ((*(byte *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + iVar3) & 1) != 0) {
        ___acrt_lowio_lock_fh(_FileHandle);
        iVar4 = -1;
        if ((*(byte *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
        }
        else {
          iVar4 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_0040d605();
        return iVar4;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c975();
  }
  return -1;
}



void FUN_0040d605(void)

{
  uint unaff_ESI;
  
  ___acrt_lowio_unlock_fh(unaff_ESI);
  return;
}



// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2015 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  ulong uVar1;
  char cVar2;
  bool bVar3;
  int iVar4;
  ulong *puVar5;
  int *piVar6;
  int iVar7;
  int unaff_EBX;
  int iVar8;
  ulong local_18 [3];
  uint local_c;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  local_c = _MaxCharCount;
  if (_MaxCharCount == 0) {
    iVar4 = 0;
    goto LAB_0040d82a;
  }
  if (_Buf == (void *)0x0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_0040c975();
    iVar4 = -1;
    goto LAB_0040d82a;
  }
  iVar8 = _FileHandle >> 6;
  iVar4 = (_FileHandle & 0x3fU) * 0x30;
  cVar2 = *(char *)((&DAT_0041b3c0)[iVar8] + 0x29 + iVar4);
  if (((cVar2 == '\x02') || (cVar2 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_0040c975();
  }
  else {
    if ((*(byte *)((&DAT_0041b3c0)[iVar8] + 0x28 + iVar4) & 0x20) != 0) {
      __lseeki64_nolock(_FileHandle,0x200000000,unaff_EBX);
    }
    bVar3 = write_requires_double_translation_nolock(_FileHandle);
    if (bVar3) {
      if (cVar2 == '\0') {
        puVar5 = (ulong *)write_double_translated_ansi_nolock
                                    ((int)local_18,(char *)_FileHandle,(uint)_Buf);
        goto LAB_0040d7b6;
      }
      if ((byte)(cVar2 - 1U) < 2) {
        puVar5 = (ulong *)write_double_translated_unicode_nolock((char *)local_18,(uint)_Buf);
        goto LAB_0040d7b6;
      }
    }
    else {
      if ((*(byte *)((&DAT_0041b3c0)[iVar8] + 0x28 + iVar4) & 0x80) == 0) {
        local_18[0] = 0;
        local_18[1] = 0;
        local_18[2] = 0;
        iVar7 = (*(code *)0x19a42)(*(undefined4 *)((&DAT_0041b3c0)[iVar8] + 0x18 + iVar4),_Buf,
                                   local_c,local_18 + 1,0);
        if (iVar7 == 0) {
          local_18[0] = (*(code *)0x1991a)();
        }
        puVar5 = local_18;
      }
      else if (cVar2 == '\0') {
        puVar5 = (ulong *)write_text_ansi_nolock((int)local_18,(char *)_FileHandle,(uint)_Buf);
      }
      else if (cVar2 == '\x01') {
        puVar5 = (ulong *)write_text_utf8_nolock((int)local_18,(char *)_FileHandle,(uint)_Buf);
      }
      else {
        if (cVar2 != '\x02') goto LAB_0040d7f1;
        puVar5 = (ulong *)write_text_utf16le_nolock((int)local_18,(char *)_FileHandle,(uint)_Buf);
      }
LAB_0040d7b6:
      uVar1 = *puVar5;
      if (puVar5[1] != 0) {
        iVar4 = puVar5[1] - puVar5[2];
        goto LAB_0040d82a;
      }
      if (uVar1 != 0) {
        if (uVar1 == 5) {
          piVar6 = __errno();
          *piVar6 = 9;
          puVar5 = ___doserrno();
          *puVar5 = 5;
        }
        else {
          ___acrt_errno_map_os_error(uVar1);
        }
        goto LAB_0040d821;
      }
    }
LAB_0040d7f1:
                    // WARNING: Load size is inaccurate
    if (((*(byte *)((&DAT_0041b3c0)[iVar8] + 0x28 + iVar4) & 0x40) != 0) && (*_Buf == '\x1a')) {
      iVar4 = 0;
      goto LAB_0040d82a;
    }
    piVar6 = __errno();
    *piVar6 = 0x1c;
    puVar5 = ___doserrno();
    *puVar5 = 0;
  }
LAB_0040d821:
  iVar4 = -1;
LAB_0040d82a:
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return iVar4;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_3518db117f0e7cdb002338c5d3c47b6c>,class <lambda_b2ea41f6bbb362cd97d94c6828d90b61> &,class
// <lambda_abdedf541bb04549bc734292b4a045d4> >(class <lambda_3518db117f0e7cdb002338c5d3c47b6c>
// &&,class <lambda_b2ea41f6bbb362cd97d94c6828d90b61> &,class
// <lambda_abdedf541bb04549bc734292b4a045d4> &&)
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_a7e850c220f1c8d1e6efeecdedd162c6>,class <lambda_46720907175c18b6c9d2717bc0d2d362> &,class
// <lambda_9048902d66e8d99359bc9897bbb930a8> >(class <lambda_a7e850c220f1c8d1e6efeecdedd162c6>
// &&,class <lambda_46720907175c18b6c9d2717bc0d2d362> &,class
// <lambda_9048902d66e8d99359bc9897bbb930a8> &&)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void operator()<>(int *param_1,undefined4 *param_2)

{
  ___acrt_lock(*param_1);
  replace_current_thread_locale_nolock
            (*(__acrt_ptd **)*param_2,(__crt_locale_data *)**(undefined4 **)param_2[1]);
  FUN_0040d87e();
  return;
}



void FUN_0040d87e(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_38edbb1296d33220d7e4dd0ed76b244a>,class <lambda_5ce1d447e08cb34b2473517608e21441> &,class
// <lambda_fb385d3da700c9147fc39e65dd577a8c> >(class <lambda_38edbb1296d33220d7e4dd0ed76b244a>
// &&,class <lambda_5ce1d447e08cb34b2473517608e21441> &,class
// <lambda_fb385d3da700c9147fc39e65dd577a8c> &&)
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_51b6e8b1eb166f2a3faf91f424b38130>,class <lambda_6250bd4b2a391816dd638c3bf72b0bcb> &,class
// <lambda_0b5a4a3e68152e1d9b943535f5f47bed> >(class <lambda_51b6e8b1eb166f2a3faf91f424b38130>
// &&,class <lambda_6250bd4b2a391816dd638c3bf72b0bcb> &,class
// <lambda_0b5a4a3e68152e1d9b943535f5f47bed> &&)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void operator()<>(int *param_1,undefined4 *param_2)

{
  int iVar1;
  int *_Memory;
  
  ___acrt_lock(*param_1);
  _Memory = *(int **)(*(int *)*param_2 + 0x48);
  if (_Memory != (int *)0x0) {
    LOCK();
    iVar1 = *_Memory;
    *_Memory = iVar1 + -1;
    UNLOCK();
    if ((iVar1 + -1 == 0) && (_Memory != &DAT_0041a628)) {
      FID_conflict__free(_Memory);
    }
  }
  FUN_0040d8df();
  return;
}



void FUN_0040d8df(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_5b71d36f03204c0beab531769a5b5694>,class <lambda_be2b3da3f62db62e9dad5dc70221a656> &,class
// <lambda_8f9ce462984622f9bf76b59e2aaaf805> >(class <lambda_5b71d36f03204c0beab531769a5b5694>
// &&,class <lambda_be2b3da3f62db62e9dad5dc70221a656> &,class
// <lambda_8f9ce462984622f9bf76b59e2aaaf805> &&)
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_6affb1475c98b40b75cdec977db92e3c>,class <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> &,class
// <lambda_608742c3c92a14382c1684fc64f96c88> >(class <lambda_6affb1475c98b40b75cdec977db92e3c>
// &&,class <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> &,class
// <lambda_608742c3c92a14382c1684fc64f96c88> &&)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void operator()<>(int *param_1,undefined4 *param_2)

{
  ___acrt_lock(*param_1);
  replace_current_thread_locale_nolock(*(__acrt_ptd **)*param_2,(__crt_locale_data *)0x0);
  FUN_0040d92a();
  return;
}



void FUN_0040d92a(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_15ade71b0218206bbe3333a0c9b79046>,class <lambda_da44e0f8b0f19ba52fefafb335991732> &,class
// <lambda_207f2d024fc103971653565357d6cd41> >(class <lambda_15ade71b0218206bbe3333a0c9b79046>
// &&,class <lambda_da44e0f8b0f19ba52fefafb335991732> &,class
// <lambda_207f2d024fc103971653565357d6cd41> &&)
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_9df27f884b057bc3edfc946cb5b7cf47>,class <lambda_e69574bed617af4e071282c136b37893> &,class
// <lambda_cc0d902bcbbeb830f749456577db4721> >(class <lambda_9df27f884b057bc3edfc946cb5b7cf47>
// &&,class <lambda_e69574bed617af4e071282c136b37893> &,class
// <lambda_cc0d902bcbbeb830f749456577db4721> &&)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void operator()<>(int *param_1,undefined4 *param_2)

{
  ___acrt_lock(*param_1);
  LOCK();
  **(int **)(*(int *)*param_2 + 0x48) = **(int **)(*(int *)*param_2 + 0x48) + 1;
  UNLOCK();
  FUN_0040d972();
  return;
}



void FUN_0040d972(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  void __cdecl __acrt_lock_and_call<class <lambda_6250bd4b2a391816dd638c3bf72b0bcb> >(enum
// __acrt_lock_id,class <lambda_6250bd4b2a391816dd638c3bf72b0bcb> &&)
// 
// Library: Visual Studio 2015 Release

void __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  
  local_c = param_1;
  local_10 = param_1;
  operator()<>((int *)&local_10,(undefined4 *)param_2);
  return;
}



// Library Function - Single Match
//  void __cdecl __acrt_lock_and_call<class <lambda_b2ea41f6bbb362cd97d94c6828d90b61> >(enum
// __acrt_lock_id,class <lambda_b2ea41f6bbb362cd97d94c6828d90b61> &&)
// 
// Library: Visual Studio 2015 Release

void __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  
  local_c = param_1;
  local_10 = param_1;
  operator()<>((int *)&local_10,(undefined4 *)param_2);
  return;
}



// Library Function - Single Match
//  void __cdecl __acrt_lock_and_call<class <lambda_be2b3da3f62db62e9dad5dc70221a656> >(enum
// __acrt_lock_id,class <lambda_be2b3da3f62db62e9dad5dc70221a656> &&)
// 
// Library: Visual Studio 2015 Release

void __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  
  local_c = param_1;
  local_10 = param_1;
  operator()<>((int *)&local_10,(undefined4 *)param_2);
  return;
}



// Library Function - Single Match
//  void __cdecl __acrt_lock_and_call<class <lambda_e69574bed617af4e071282c136b37893> >(enum
// __acrt_lock_id,class <lambda_e69574bed617af4e071282c136b37893> &&)
// 
// Library: Visual Studio 2015 Release

void __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  
  local_c = param_1;
  local_10 = param_1;
  operator()<>((int *)&local_10,(undefined4 *)param_2);
  return;
}



// Library Function - Single Match
//  void __cdecl construct_ptd(struct __acrt_ptd * const,struct __crt_locale_data * * const)
// 
// Library: Visual Studio 2015 Release

void __cdecl construct_ptd(__acrt_ptd *param_1,__crt_locale_data **param_2)

{
  __acrt_ptd **local_c;
  __acrt_ptd **local_8;
  
  *(undefined4 *)(param_1 + 0x18) = 1;
  *(undefined **)param_1 = &DAT_00414c20;
  *(undefined4 *)(param_1 + 0x350) = 1;
  *(undefined4 **)(param_1 + 0x48) = &DAT_0041a628;
  *(undefined2 *)(param_1 + 0x6c) = 0x43;
  *(undefined2 *)(param_1 + 0x172) = 0x43;
  *(undefined4 *)(param_1 + 0x34c) = 0;
  local_8 = &param_1;
  __acrt_lock_and_call<>(5,(<> *)&local_8);
  local_c = &param_1;
  local_8 = (__acrt_ptd **)&param_2;
  __acrt_lock_and_call<>(4,(<> *)&local_c);
  return;
}



// Library Function - Single Match
//  void __stdcall destroy_fls(void *)
// 
// Library: Visual Studio 2015 Release

void destroy_fls(void *param_1)

{
  if (param_1 != (void *)0x0) {
    destroy_ptd((__acrt_ptd *)param_1);
    FID_conflict__free(param_1);
  }
  return;
}



// Library Function - Single Match
//  void __cdecl destroy_ptd(struct __acrt_ptd * const)
// 
// Library: Visual Studio 2015 Release

void __cdecl destroy_ptd(__acrt_ptd *param_1)

{
  __acrt_ptd **local_8;
  
  if (*(undefined **)param_1 != &DAT_00414c20) {
    FID_conflict__free(*(undefined **)param_1);
  }
  FID_conflict__free(*(void **)(param_1 + 0x3c));
  FID_conflict__free(*(void **)(param_1 + 0x30));
  FID_conflict__free(*(void **)(param_1 + 0x34));
  FID_conflict__free(*(void **)(param_1 + 0x38));
  FID_conflict__free(*(void **)(param_1 + 0x28));
  FID_conflict__free(*(void **)(param_1 + 0x2c));
  FID_conflict__free(*(void **)(param_1 + 0x40));
  FID_conflict__free(*(void **)(param_1 + 0x44));
  FID_conflict__free(*(void **)(param_1 + 0x360));
  local_8 = &param_1;
  __acrt_lock_and_call<>(5,(<> *)&local_8);
  local_8 = &param_1;
  __acrt_lock_and_call<>(4,(<> *)&local_8);
  return;
}



// Library Function - Single Match
//  void __cdecl replace_current_thread_locale_nolock(struct __acrt_ptd * const,struct
// __crt_locale_data * const)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __cdecl replace_current_thread_locale_nolock(__acrt_ptd *param_1,__crt_locale_data *param_2)

{
  undefined **ppuVar1;
  
  if (*(int *)(param_1 + 0x4c) != 0) {
    ___acrt_release_locale_ref(*(int *)(param_1 + 0x4c));
    ppuVar1 = *(undefined ***)(param_1 + 0x4c);
    if (((ppuVar1 != DAT_0041b5c4) && (ppuVar1 != &PTR_DAT_0041a850)) &&
       (ppuVar1[3] == (undefined *)0x0)) {
      ___acrt_free_locale(ppuVar1);
    }
  }
  *(__crt_locale_data **)(param_1 + 0x4c) = param_2;
  if (param_2 != (__crt_locale_data *)0x0) {
    ___acrt_add_locale_ref((int)param_2);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_getptd
// 
// Library: Visual Studio 2015 Release

__acrt_ptd * ___acrt_getptd(void)

{
  undefined4 uVar1;
  __acrt_ptd *_Memory;
  int iVar2;
  
  uVar1 = (*(code *)0x1991a)();
  if ((DAT_0041a328 != -1) &&
     (_Memory = (__acrt_ptd *)___acrt_FlsGetValue_4(DAT_0041a328), _Memory != (__acrt_ptd *)0x0)) {
LAB_0040dc17:
    (*(code *)0x199ea)(uVar1);
    return _Memory;
  }
  _Memory = (__acrt_ptd *)__calloc_base(1,0x364);
  if ((_Memory == (__acrt_ptd *)0x0) ||
     (iVar2 = ___acrt_FlsSetValue_8(DAT_0041a328,_Memory), iVar2 == 0)) {
    FID_conflict__free(_Memory);
  }
  else {
    construct_ptd(_Memory,(__crt_locale_data **)&DAT_0041b5c4);
    FID_conflict__free((void *)0x0);
    if (_Memory != (__acrt_ptd *)0x0) goto LAB_0040dc17;
  }
  (*(code *)0x199ea)(uVar1);
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  ___acrt_getptd_noexit
// 
// Library: Visual Studio 2015 Release

__acrt_ptd * ___acrt_getptd_noexit(void)

{
  undefined4 uVar1;
  __acrt_ptd *_Memory;
  int iVar2;
  
  uVar1 = (*(code *)0x1991a)();
  if ((DAT_0041a328 != -1) &&
     (_Memory = (__acrt_ptd *)___acrt_FlsGetValue_4(DAT_0041a328), _Memory != (__acrt_ptd *)0x0)) {
LAB_0040dca6:
    (*(code *)0x199ea)(uVar1);
    return _Memory;
  }
  _Memory = (__acrt_ptd *)__calloc_base(1,0x364);
  if (_Memory == (__acrt_ptd *)0x0) {
    _Memory = (__acrt_ptd *)0x0;
  }
  else {
    iVar2 = ___acrt_FlsSetValue_8(DAT_0041a328,_Memory);
    if (iVar2 != 0) {
      construct_ptd(_Memory,(__crt_locale_data **)&DAT_0041b5c4);
      FID_conflict__free((void *)0x0);
      if (_Memory != (__acrt_ptd *)0x0) goto LAB_0040dca6;
      goto LAB_0040dc9d;
    }
  }
  FID_conflict__free(_Memory);
LAB_0040dc9d:
  (*(code *)0x199ea)(uVar1);
  return (__acrt_ptd *)0x0;
}



// Library Function - Single Match
//  ___acrt_uninitialize_ptd
// 
// Library: Visual Studio 2015 Release

undefined4 ___acrt_uninitialize_ptd(void)

{
  int iVar1;
  
  iVar1 = DAT_0041a328;
  if (DAT_0041a328 != -1) {
    iVar1 = ___acrt_FlsFree_4(DAT_0041a328);
    DAT_0041a328 = -1;
  }
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



uint __cdecl FUN_0040dcfb(uint param_1,uint param_2)

{
  if (param_1 < param_2) {
    return 0xffffffff;
  }
  return (uint)(param_2 < param_1);
}



// Library Function - Single Match
//  int __cdecl common_expand_argv_wildcards<char>(char * * const,char * * * const)
// 
// Library: Visual Studio 2015 Release

int __cdecl common_expand_argv_wildcards<char>(char **param_1,char ***param_2)

{
  char *pcVar1;
  char cVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  char *pcVar6;
  int iVar7;
  char **ppcVar8;
  char *pcVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  undefined4 *local_24;
  undefined4 *local_20;
  undefined4 local_1c;
  int local_18;
  char **local_14;
  char **local_10;
  char *local_c;
  undefined4 local_8;
  
  if (param_2 == (char ***)0x0) {
    piVar5 = __errno();
    iVar7 = 0x16;
    *piVar5 = 0x16;
    FUN_0040c975();
  }
  else {
    *param_2 = (char **)0x0;
    local_24 = (undefined4 *)0x0;
    local_20 = (undefined4 *)0x0;
    local_1c = 0;
    pcVar6 = *param_1;
    puVar11 = local_24;
    puVar3 = local_20;
    while (local_24 = puVar11, local_20 = puVar3, pcVar6 != (char *)0x0) {
      uVar4 = (uint)local_8 >> 0x18;
      local_8 = (char *)CONCAT13((char)uVar4,0x3f2a);
      pcVar6 = _strpbrk(*param_1,(char *)&local_8);
      if (pcVar6 == (char *)0x0) {
        iVar7 = copy_and_add_argument_to_buffer<char>
                          (*param_1,(char *)0x0,0,(argument_list<char> *)&local_24);
      }
      else {
        iVar7 = expand_argument_wildcards<char>(*param_1,pcVar6,(argument_list<char> *)&local_24);
      }
      if (iVar7 != 0) goto LAB_0040de85;
      param_1 = param_1 + 1;
      puVar11 = local_24;
      puVar3 = local_20;
      pcVar6 = *param_1;
    }
    local_c = (char *)0x0;
    local_8 = (char *)0x0;
    local_10 = (char **)(((int)puVar3 - (int)puVar11 >> 2) + 1);
    pcVar6 = (char *)(~-(uint)(puVar3 < puVar11) & ((int)puVar3 - (int)puVar11) + 3U >> 2);
    if (pcVar6 != (char *)0x0) {
      local_8 = (char *)0x0;
      puVar10 = puVar11;
      do {
        pcVar9 = (char *)*puVar10;
        pcVar1 = pcVar9 + 1;
        do {
          cVar2 = *pcVar9;
          pcVar9 = pcVar9 + 1;
        } while (cVar2 != '\0');
        local_8 = pcVar9 + (int)(local_8 + (1 - (int)pcVar1));
        puVar10 = puVar10 + 1;
        local_c = local_c + 1;
      } while (local_c != pcVar6);
    }
    ppcVar8 = (char **)___acrt_allocate_buffer_for_argv((uint)local_10,(uint)local_8,1);
    if (ppcVar8 == (char **)0x0) {
      iVar7 = -1;
    }
    else {
      local_10 = ppcVar8 + (int)local_10;
      local_14 = local_10;
      if (puVar11 != puVar3) {
        local_18 = (int)ppcVar8 - (int)puVar11;
        do {
          local_c = (char *)*puVar11;
          pcVar6 = local_c + 1;
          do {
            cVar2 = *local_c;
            local_c = local_c + 1;
          } while (cVar2 != '\0');
          local_c = local_c + (1 - (int)pcVar6);
          iVar7 = FUN_00410ceb((char *)local_10,
                               (uint)((int)local_14 + ((int)local_8 - (int)local_10)),
                               (char *)*puVar11,(uint)local_c);
          if (iVar7 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          *(char ***)(local_18 + (int)puVar11) = local_10;
          puVar11 = puVar11 + 1;
          local_10 = (char **)((int)local_10 + (int)local_c);
        } while (puVar11 != puVar3);
      }
      iVar7 = 0;
      *param_2 = ppcVar8;
    }
    FID_conflict__free((void *)0x0);
LAB_0040de85:
    _anon_FD16DE3C::argument_list<char>::~argument_list<char>((argument_list<char> *)&local_24);
  }
  return iVar7;
}



// Library Function - Single Match
//  int __cdecl copy_and_add_argument_to_buffer<char>(char const * const,char const * const,unsigned
// int,class `anonymous namespace'::argument_list<char> &)
// 
// Library: Visual Studio 2015 Release

int __cdecl
copy_and_add_argument_to_buffer<char>
          (char *param_1,char *param_2,uint param_3,argument_list<char> *param_4)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  
  pcVar4 = param_1;
  do {
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  pcVar4 = pcVar4 + (1 - (int)(param_1 + 1));
  if ((char *)(-1 - param_3) < pcVar4) {
    iVar3 = 0xc;
  }
  else {
    pcVar5 = pcVar4 + param_3 + 1;
    pcVar2 = (char *)__calloc_base((uint)pcVar5,1);
    if (param_3 != 0) {
      iVar3 = FUN_00410ceb(pcVar2,(uint)pcVar5,param_2,param_3);
      if (iVar3 != 0) goto LAB_0040df2c;
    }
    iVar3 = FUN_00410ceb(pcVar2 + param_3,(int)pcVar5 - param_3,param_1,(uint)pcVar4);
    if (iVar3 != 0) {
LAB_0040df2c:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    iVar3 = append(param_4,pcVar2);
    FID_conflict__free((void *)0x0);
  }
  return iVar3;
}



// Library Function - Multiple Matches With Same Base Name
//  int __cdecl expand_argument_wildcards<char>(char * const,char * const,class `anonymous
// namespace'::argument_list<char> &)
//  int __cdecl expand_argument_wildcards<char>(char * const,char * const,class `anonymous
// namespace'::argument_list<char> &)
// 
// Library: Visual Studio 2015 Release

int __cdecl
expand_argument_wildcards<char>(char *param_1,char *param_2,argument_list<char> *param_3)

{
  uchar uVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined1 local_148 [44];
  char local_11c;
  char local_11b;
  char local_11a;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  for (; (((param_2 != param_1 && (uVar1 = *param_2, uVar1 != '/')) && (uVar1 != '\\')) &&
         (uVar1 != ':')); param_2 = (char *)__mbsdec((uchar *)param_1,(uchar *)param_2)) {
  }
  uVar1 = *param_2;
  if ((uVar1 == ':') && (param_2 != param_1 + 1)) {
    iVar3 = copy_and_add_argument_to_buffer<char>(param_1,(char *)0x0,0,param_3);
  }
  else {
    if ((uVar1 == '/') || ((uVar1 == '\\' || (uVar1 == ':')))) {
      bVar2 = 1;
    }
    else {
      bVar2 = 0;
    }
    _memset(local_148,0,0x140);
    iVar4 = (*(code *)0x19b26)(param_1,0,local_148,0,0,0);
    if (iVar4 == -1) {
      iVar3 = copy_and_add_argument_to_buffer<char>(param_1,(char *)0x0,0,param_3);
    }
    else {
      iVar6 = *(int *)(param_3 + 4) - *(int *)param_3 >> 2;
      do {
        if (((local_11c != '.') ||
            ((local_11b != '\0' && ((local_11b != '.' || (local_11a != '\0')))))) &&
           (iVar3 = copy_and_add_argument_to_buffer<char>
                              (&local_11c,param_1,
                               -(uint)bVar2 & (uint)((uchar *)param_2 + (1 - (int)param_1)),param_3)
           , iVar3 != 0)) goto LAB_0040e009;
        iVar3 = (*(code *)0x19b3a)(iVar4,local_148);
      } while (iVar3 != 0);
      iVar5 = *(int *)(param_3 + 4) - *(int *)param_3 >> 2;
      iVar3 = 0;
      if (iVar6 != iVar5) {
        _qsort((void *)(*(int *)param_3 + iVar6 * 4),iVar5 - iVar6,4,FUN_0040dcfb);
      }
    }
LAB_0040e009:
    if (iVar4 != -1) {
      (*(code *)0x19b1a)(iVar4);
    }
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __thiscall `anonymous namespace'::argument_list<char>::~argument_list<char>(void)
//  public: __thiscall `anonymous namespace'::argument_list<char>::~argument_list<char>(void)
//  public: __thiscall `anonymous namespace'::argument_list<wchar_t>::~argument_list<wchar_t>(void)
//  public: __thiscall `anonymous namespace'::argument_list<wchar_t>::~argument_list<wchar_t>(void)
// 
// Library: Visual Studio 2015 Release

void __thiscall _anon_FD16DE3C::argument_list<char>::~argument_list<char>(argument_list<char> *this)

{
  undefined4 *puVar1;
  
  for (puVar1 = *(undefined4 **)this; puVar1 != *(undefined4 **)(this + 4); puVar1 = puVar1 + 1) {
    FID_conflict__free((void *)*puVar1);
  }
  FID_conflict__free(*(void **)this);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall `anonymous namespace'::argument_list<char>::append(char * const)
//  public: int __thiscall `anonymous namespace'::argument_list<char>::append(char * const)
//  public: int __thiscall `anonymous namespace'::argument_list<wchar_t>::append(wchar_t * const)
//  public: int __thiscall `anonymous namespace'::argument_list<wchar_t>::append(wchar_t * const)
// 
// Library: Visual Studio 2015 Release

int __thiscall append(void *this,void *param_1)

{
  int iVar1;
  
  iVar1 = expand_if_necessary((int *)this);
  if (iVar1 == 0) {
    **(undefined4 **)((int)this + 4) = param_1;
    *(int *)((int)this + 4) = *(int *)((int)this + 4) + 4;
    iVar1 = 0;
  }
  else {
    FID_conflict__free(param_1);
  }
  return iVar1;
}



// Library Function - Multiple Matches With Same Base Name
//  private: int __thiscall `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
//  private: int __thiscall `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
//  private: int __thiscall `anonymous namespace'::argument_list<wchar_t>::expand_if_necessary(void)
//  private: int __thiscall `anonymous namespace'::argument_list<wchar_t>::expand_if_necessary(void)
// 
// Library: Visual Studio 2015 Release

undefined4 __fastcall expand_if_necessary(int *param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  
  if (param_1[1] == param_1[2]) {
    if (*param_1 == 0) {
      iVar2 = __calloc_base(4,4);
      *param_1 = iVar2;
      FID_conflict__free((void *)0x0);
      iVar2 = *param_1;
      if (iVar2 != 0) {
        param_1[1] = iVar2;
        param_1[2] = iVar2 + 0x10;
        goto LAB_0040e125;
      }
    }
    else {
      uVar3 = param_1[2] - *param_1 >> 2;
      if (uVar3 < 0x80000000) {
        iVar2 = FUN_0040fb85((void *)*param_1,uVar3 * 2,4);
        if (iVar2 == 0) {
          uVar1 = 0xc;
        }
        else {
          *param_1 = iVar2;
          param_1[1] = iVar2 + uVar3 * 4;
          param_1[2] = iVar2 + uVar3 * 8;
          uVar1 = 0;
        }
        FID_conflict__free((void *)0x0);
        return uVar1;
      }
    }
    uVar1 = 0xc;
  }
  else {
LAB_0040e125:
    uVar1 = 0;
  }
  return uVar1;
}



void __cdecl FUN_0040e19e(char **param_1,char ***param_2)

{
  common_expand_argv_wildcards<char>(param_1,param_2);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_978dc153c237d78434369da87b74ff60>,class <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> &,class
// <lambda_4a8533e2866a575feecb8298ce776b0d> >(class <lambda_978dc153c237d78434369da87b74ff60>
// &&,class <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> &,class
// <lambda_4a8533e2866a575feecb8298ce776b0d> &&)
// 
// Library: Visual Studio 2015 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  ___acrt_lock(*(int *)param_1);
  <>::operator()(param_2);
  FUN_0040e1e0();
  return;
}



void FUN_0040e1e0(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  void __cdecl __acrt_lock_and_call<class <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> >(enum
// __acrt_lock_id,class <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c> &&)
// 
// Library: Visual Studio 2015 Release

void __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  __crt_seh_guarded_call<void> local_5;
  
  local_c = param_1;
  local_10 = param_1;
  __crt_seh_guarded_call<void>::operator()<>(&local_5,(<> *)&local_10,param_2,(<> *)&local_c);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  public: void __thiscall <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c>::operator()(void)const 
// 
// Library: Visual Studio 2015 Release

void __thiscall <>::operator()(<> *this)

{
  int iVar1;
  
  _DAT_0041b2b0 = *(undefined4 *)(*(int *)(**(int **)this + 0x48) + 4);
  _DAT_0041b2b4 = *(undefined4 *)(*(int *)(**(int **)this + 0x48) + 8);
  _DAT_0041b2ac = *(undefined4 *)(*(int *)(**(int **)this + 0x48) + 0x21c);
  _memcpy_s(&DAT_0041b2b8,0xc,(void *)(*(int *)(**(int **)this + 0x48) + 0xc),0xc);
  _memcpy_s(&DAT_0041a420,0x101,(void *)(*(int *)(**(int **)this + 0x48) + 0x18),0x101);
  _memcpy_s(&DAT_0041a528,0x100,(void *)(*(int *)(**(int **)this + 0x48) + 0x119),0x100);
  LOCK();
  iVar1 = *(int *)PTR_DAT_0041a848;
  *(int *)PTR_DAT_0041a848 = iVar1 + -1;
  UNLOCK();
  if ((iVar1 + -1 == 0) && ((undefined4 *)PTR_DAT_0041a848 != &DAT_0041a628)) {
    FID_conflict__free(PTR_DAT_0041a848);
  }
  PTR_DAT_0041a848 = *(undefined **)(**(int **)this + 0x48);
  LOCK();
  **(int **)(**(int **)this + 0x48) = **(int **)(**(int **)this + 0x48) + 1;
  UNLOCK();
  return;
}



// Library Function - Single Match
//  wchar_t const * __cdecl CPtoLocaleName(int)
// 
// Library: Visual Studio 2015 Release

wchar_t * __cdecl CPtoLocaleName(int param_1)

{
  if (param_1 == 0x3a4) {
    return L"ja-JP";
  }
  if (param_1 == 0x3a8) {
    return L"zh-CN";
  }
  if (param_1 == 0x3b5) {
    return L"ko-KR";
  }
  if (param_1 != 0x3b6) {
    return (wchar_t *)0x0;
  }
  return L"zh-TW";
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2015 Release

int __cdecl getSystemCP(int param_1)

{
  int local_14;
  int local_10;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,(__crt_locale_pointers *)0x0);
  DAT_0041b2c4 = 0;
  if (param_1 == -2) {
    DAT_0041b2c4 = 1;
    param_1 = (*(code *)0x19b5c)();
  }
  else if (param_1 == -3) {
    DAT_0041b2c4 = 1;
    param_1 = (*(code *)0x19ab4)();
  }
  else if (param_1 == -4) {
    DAT_0041b2c4 = 1;
    param_1 = *(int *)(local_10 + 8);
  }
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return param_1;
}



// Library Function - Single Match
//  void __cdecl setSBCS(struct __crt_multibyte_data *)
// 
// Library: Visual Studio 2015 Release

void __cdecl setSBCS(__crt_multibyte_data *param_1)

{
  int iVar1;
  __crt_multibyte_data *p_Var2;
  
  p_Var2 = param_1 + 0x18;
  _memset(p_Var2,0,0x101);
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x21c) = 0;
  iVar1 = 0x101;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  do {
    *p_Var2 = p_Var2[(int)&DAT_0041a628 - (int)param_1];
    p_Var2 = p_Var2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  p_Var2 = param_1 + 0x119;
  iVar1 = 0x100;
  do {
    *p_Var2 = p_Var2[(int)&DAT_0041a628 - (int)param_1];
    p_Var2 = p_Var2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct __crt_multibyte_data *)
// 
// Library: Visual Studio 2015 Release

void __cdecl setSBUpLow(__crt_multibyte_data *param_1)

{
  byte bVar1;
  __crt_multibyte_data _Var2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  __crt_multibyte_data *p_Var6;
  undefined1 local_71c [6];
  byte local_716;
  byte local_715 [13];
  ushort local_708 [512];
  __crt_multibyte_data local_308 [256];
  __crt_multibyte_data local_208 [256];
  char local_108 [256];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  iVar3 = (*(code *)0x19b68)(*(undefined4 *)(param_1 + 4),local_71c);
  if (iVar3 == 0) {
    uVar4 = 0;
    do {
      p_Var6 = param_1 + uVar4 + 0x119;
      if (p_Var6 + (-0x61 - (int)(param_1 + 0x119)) + 0x20 < (__crt_multibyte_data *)0x1a) {
        param_1[uVar4 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar4 + 0x19] | 0x10);
        _Var2 = (__crt_multibyte_data)((char)uVar4 + ' ');
LAB_0040e55a:
        *p_Var6 = _Var2;
      }
      else {
        if (p_Var6 + (-0x61 - (int)(param_1 + 0x119)) < (__crt_multibyte_data *)0x1a) {
          param_1[uVar4 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar4 + 0x19] | 0x20);
          _Var2 = (__crt_multibyte_data)((char)uVar4 + -0x20);
          goto LAB_0040e55a;
        }
        *p_Var6 = (__crt_multibyte_data)0x0;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  else {
    uVar4 = 0;
    do {
      local_108[uVar4] = (char)uVar4;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
    pbVar5 = &local_716;
    local_108[0] = ' ';
    while (local_716 != 0) {
      bVar1 = pbVar5[1];
      for (uVar4 = (uint)local_716; (uVar4 <= bVar1 && (uVar4 < 0x100)); uVar4 = uVar4 + 1) {
        local_108[uVar4] = ' ';
      }
      pbVar5 = pbVar5 + 2;
      local_716 = *pbVar5;
    }
    ___acrt_GetStringTypeA
              ((__crt_locale_pointers *)0x0,1,local_108,0x100,local_708,*(int *)(param_1 + 4),0);
    ___acrt_LCMapStringA
              ((__crt_locale_pointers *)0x0,*(wchar_t **)(param_1 + 0x21c),0x100,local_108,0x100,
               (char *)local_208,0x100,*(int *)(param_1 + 4),0);
    ___acrt_LCMapStringA
              ((__crt_locale_pointers *)0x0,*(wchar_t **)(param_1 + 0x21c),0x200,local_108,0x100,
               (char *)local_308,0x100,*(int *)(param_1 + 4),0);
    uVar4 = 0;
    do {
      if ((local_708[uVar4] & 1) == 0) {
        if ((local_708[uVar4] & 2) != 0) {
          param_1[uVar4 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar4 + 0x19] | 0x20);
          _Var2 = local_308[uVar4];
          goto LAB_0040e501;
        }
        param_1[uVar4 + 0x119] = (__crt_multibyte_data)0x0;
      }
      else {
        param_1[uVar4 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar4 + 0x19] | 0x10);
        _Var2 = local_208[uVar4];
LAB_0040e501:
        param_1[uVar4 + 0x119] = _Var2;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  int __cdecl setmbcp_internal(int,bool)
// 
// Library: Visual Studio 2015 Release

int __cdecl setmbcp_internal(int param_1,bool param_2)

{
  int iVar1;
  __crt_multibyte_data *p_Var2;
  int *piVar3;
  int iVar4;
  undefined4 *puVar5;
  __crt_multibyte_data *p_Var6;
  __acrt_ptd **local_10 [2];
  __acrt_ptd *local_8;
  
  local_8 = ___acrt_getptd();
  ___acrt_update_thread_multibyte_data();
  local_10[0] = (__acrt_ptd **)getSystemCP(param_1);
  if (local_10[0] == *(__acrt_ptd ***)(*(int *)(local_8 + 0x48) + 4)) {
    return 0;
  }
  p_Var2 = (__crt_multibyte_data *)__malloc_base(0x220);
  if (p_Var2 != (__crt_multibyte_data *)0x0) {
    puVar5 = *(undefined4 **)(local_8 + 0x48);
    p_Var6 = p_Var2;
    for (iVar4 = 0x88; iVar4 != 0; iVar4 = iVar4 + -1) {
      *(undefined4 *)p_Var6 = *puVar5;
      puVar5 = puVar5 + 1;
      p_Var6 = p_Var6 + 4;
    }
    *(undefined4 *)p_Var2 = 0;
    iVar4 = __setmbcp_nolock((int)local_10[0],p_Var2);
    if (iVar4 != -1) {
      if (!param_2) {
        ___acrt_set_locale_changed();
      }
      piVar3 = *(int **)(local_8 + 0x48);
      LOCK();
      iVar1 = *piVar3;
      *piVar3 = *piVar3 + -1;
      UNLOCK();
      if ((iVar1 == 1) && (*(undefined4 **)(local_8 + 0x48) != &DAT_0041a628)) {
        FID_conflict__free(*(void **)(local_8 + 0x48));
      }
      *(undefined4 *)p_Var2 = 1;
      p_Var6 = (__crt_multibyte_data *)0x0;
      *(__crt_multibyte_data **)(local_8 + 0x48) = p_Var2;
      if ((((byte)local_8[0x350] & 2) == 0) && (((byte)DAT_0041a970 & 1) == 0)) {
        local_10[0] = &local_8;
        __acrt_lock_and_call<>(5,(<> *)local_10);
        if (param_2) {
          PTR_DAT_0041a90c = PTR_DAT_0041a848;
        }
      }
      goto LAB_0040e5f9;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  iVar4 = -1;
  p_Var6 = p_Var2;
LAB_0040e5f9:
  FID_conflict__free(p_Var6);
  return iVar4;
}



// Library Function - Single Match
//  ___acrt_initialize_multibyte
// 
// Library: Visual Studio 2015 Release

undefined4 ___acrt_initialize_multibyte(void)

{
  int in_EAX;
  
  if (DAT_0041b2c8 == '\0') {
    in_EAX = setmbcp_internal(-3,true);
    DAT_0041b2c8 = '\x01';
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___acrt_update_thread_multibyte_data
// 
// Library: Visual Studio 2015 Release

int * ___acrt_update_thread_multibyte_data(void)

{
  int iVar1;
  __acrt_ptd *p_Var2;
  int *_Memory;
  
  p_Var2 = ___acrt_getptd();
  if (((*(uint *)(p_Var2 + 0x350) & DAT_0041a970) == 0) || (*(int *)(p_Var2 + 0x4c) == 0)) {
    ___acrt_lock(5);
    _Memory = *(int **)(p_Var2 + 0x48);
    if (_Memory != (int *)PTR_DAT_0041a848) {
      if (_Memory != (int *)0x0) {
        LOCK();
        iVar1 = *_Memory;
        *_Memory = iVar1 + -1;
        UNLOCK();
        if ((iVar1 + -1 == 0) && (_Memory != &DAT_0041a628)) {
          FID_conflict__free(_Memory);
        }
      }
      *(undefined **)(p_Var2 + 0x48) = PTR_DAT_0041a848;
      _Memory = (int *)PTR_DAT_0041a848;
      LOCK();
      *(int *)PTR_DAT_0041a848 = *(int *)PTR_DAT_0041a848 + 1;
      UNLOCK();
    }
    FUN_0040e732();
  }
  else {
    _Memory = *(int **)(p_Var2 + 0x48);
  }
  if (_Memory == (int *)0x0) {
                    // WARNING: Subroutine does not return
    _abort();
  }
  return _Memory;
}



void FUN_0040e732(void)

{
  ___acrt_unlock(5);
  return;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2015 Release

void __cdecl __setmbcp_nolock(int param_1,__crt_multibyte_data *param_2)

{
  byte bVar1;
  undefined2 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  __crt_multibyte_data *p_Var7;
  wchar_t *pwVar8;
  byte *pbVar9;
  undefined2 *puVar10;
  uint uVar11;
  int local_20;
  uint local_1c;
  byte local_16 [14];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  uVar3 = getSystemCP(param_1);
  if (uVar3 != 0) {
    uVar11 = 0;
    uVar4 = 0;
    local_20 = 0;
LAB_0040e781:
    if (*(uint *)((int)&DAT_0041a330 + uVar4) != uVar3) goto code_r0x0040e78d;
    _memset(param_2 + 0x18,0,0x101);
    pbVar6 = &DAT_0041a340 + local_20 * 0x30;
    do {
      bVar1 = *pbVar6;
      pbVar9 = pbVar6;
      while ((bVar1 != 0 && (bVar1 = pbVar9[1], bVar1 != 0))) {
        for (uVar4 = (uint)*pbVar9; (uVar4 <= bVar1 && (uVar4 < 0x100)); uVar4 = uVar4 + 1) {
          param_2[uVar4 + 0x19] =
               (__crt_multibyte_data)((byte)param_2[uVar4 + 0x19] | (&DAT_0041a32c)[uVar11]);
          bVar1 = pbVar9[1];
        }
        pbVar9 = pbVar9 + 2;
        bVar1 = *pbVar9;
      }
      uVar11 = uVar11 + 1;
      pbVar6 = pbVar6 + 8;
    } while (uVar11 < 4);
    *(uint *)(param_2 + 4) = uVar3;
    *(undefined4 *)(param_2 + 8) = 1;
    pwVar8 = CPtoLocaleName(uVar3);
    *(wchar_t **)(param_2 + 0x21c) = pwVar8;
    p_Var7 = param_2 + 0xc;
    puVar10 = (undefined2 *)(&DAT_0041a334 + local_20 * 0x30);
    iVar5 = 6;
    do {
      uVar2 = *puVar10;
      puVar10 = puVar10 + 1;
      *(undefined2 *)p_Var7 = uVar2;
      p_Var7 = p_Var7 + 2;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    goto LAB_0040e91a;
  }
  setSBCS(param_2);
LAB_0040e924:
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0040e78d:
  local_20 = local_20 + 1;
  uVar4 = uVar4 + 0x30;
  if (0xef < uVar4) goto code_r0x0040e79b;
  goto LAB_0040e781;
code_r0x0040e79b:
  if (((uVar3 != 65000) && (uVar3 != 0xfde9)) &&
     (iVar5 = (*(code *)0x19b4a)(uVar3 & 0xffff), iVar5 != 0)) {
    iVar5 = (*(code *)0x19b68)(uVar3,&local_1c);
    if (iVar5 == 0) {
      if (DAT_0041b2c4 != 0) {
        setSBCS(param_2);
      }
    }
    else {
      _memset(param_2 + 0x18,0,0x101);
      *(uint *)(param_2 + 4) = uVar3;
      *(undefined4 *)(param_2 + 0x21c) = 0;
      if (local_1c < 2) {
        *(undefined4 *)(param_2 + 8) = 0;
      }
      else {
        pbVar6 = local_16;
        while ((local_16[0] != 0 && (bVar1 = pbVar6[1], bVar1 != 0))) {
          for (uVar3 = (uint)*pbVar6; uVar3 <= bVar1; uVar3 = uVar3 + 1) {
            param_2[uVar3 + 0x19] = (__crt_multibyte_data)((byte)param_2[uVar3 + 0x19] | 4);
          }
          pbVar6 = pbVar6 + 2;
          local_16[0] = *pbVar6;
        }
        p_Var7 = param_2 + 0x1a;
        iVar5 = 0xfe;
        do {
          *p_Var7 = (__crt_multibyte_data)((byte)*p_Var7 | 8);
          p_Var7 = p_Var7 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
        pwVar8 = CPtoLocaleName(*(int *)(param_2 + 4));
        *(wchar_t **)(param_2 + 0x21c) = pwVar8;
        *(undefined4 *)(param_2 + 8) = 1;
      }
      *(undefined4 *)(param_2 + 0xc) = 0;
      *(undefined4 *)(param_2 + 0x10) = 0;
      *(undefined4 *)(param_2 + 0x14) = 0;
LAB_0040e91a:
      setSBUpLow(param_2);
    }
  }
  goto LAB_0040e924;
}



// Library Function - Single Match
//  _memcpy_s
// 
// Libraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
    eVar1 = 0;
  }
  else if (_Dst == (void *)0x0) {
    piVar2 = __errno();
    eVar1 = 0x16;
    *piVar2 = 0x16;
    FUN_0040c975();
  }
  else if ((_Src == (void *)0x0) || (_DstSize < _MaxCount)) {
    _memset(_Dst,0,_DstSize);
    if (_Src == (void *)0x0) {
      piVar2 = __errno();
      eVar1 = 0x16;
    }
    else {
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      piVar2 = __errno();
      eVar1 = 0x22;
    }
    *piVar2 = eVar1;
    FUN_0040c975();
  }
  else {
    FUN_00413220((uint *)_Dst,(uint *)_Src,_MaxCount);
    eVar1 = 0;
  }
  return eVar1;
}



// Library Function - Single Match
//  int __cdecl x_ismbbtype_l(struct __crt_locale_pointers *,unsigned int,int,int)
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release, Visual Studio 2017 Debug, Visual
// Studio 2017 Release

int __cdecl x_ismbbtype_l(__crt_locale_pointers *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  int local_14;
  int *local_10;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,param_1);
  if ((*(byte *)(local_c + 0x19 + (param_2 & 0xff)) & (byte)param_4) == 0) {
    iVar2 = 0;
    if (param_3 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = (uint)*(ushort *)(*local_10 + (param_2 & 0xff) * 2) & param_3;
    }
    if (uVar1 == 0) goto LAB_0040e9f7;
  }
  iVar2 = 1;
LAB_0040e9f7:
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return iVar2;
}



// Library Function - Single Match
//  __ismbblead
// 
// Library: Visual Studio 2015 Release

int __cdecl __ismbblead(uint _C)

{
  int iVar1;
  
  iVar1 = x_ismbbtype_l((__crt_locale_pointers *)0x0,_C,0,4);
  return iVar1;
}



// Library Function - Single Match
//  wchar_t const * __cdecl find_end_of_double_null_terminated_sequence(wchar_t const * const)
// 
// Library: Visual Studio 2015 Release

wchar_t * __cdecl find_end_of_double_null_terminated_sequence(wchar_t *param_1)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  wVar1 = *param_1;
  while (wVar1 != L'\0') {
    pwVar2 = param_1;
    do {
      wVar1 = *pwVar2;
      pwVar2 = pwVar2 + 1;
    } while (wVar1 != L'\0');
    param_1 = param_1 + ((int)pwVar2 - (int)(param_1 + 1) >> 1) + 1;
    wVar1 = *param_1;
  }
  return param_1 + 1;
}



// Library Function - Single Match
//  ___dcrt_get_narrow_environment_from_os
// 
// Library: Visual Studio 2015 Release

void * ___dcrt_get_narrow_environment_from_os(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  size_t sVar3;
  void *_Memory;
  int iVar4;
  void *pvVar5;
  
  pwVar1 = (wchar_t *)(*(code *)0x19b98)();
  if (pwVar1 != (wchar_t *)0x0) {
    pwVar2 = find_end_of_double_null_terminated_sequence(pwVar1);
    iVar4 = (int)pwVar2 - (int)pwVar1 >> 1;
    sVar3 = (*(code *)0x19a7a)(0,0,pwVar1,iVar4,0,0,0,0);
    if (sVar3 != 0) {
      _Memory = (void *)__malloc_base(sVar3);
      if (_Memory == (void *)0x0) {
LAB_0040ead8:
        pvVar5 = (void *)0x0;
      }
      else {
        iVar4 = (*(code *)0x19a7a)(0,0,pwVar1,iVar4,_Memory,sVar3,0,0);
        if (iVar4 == 0) goto LAB_0040ead8;
        pvVar5 = _Memory;
        _Memory = (void *)0x0;
      }
      FID_conflict__free(_Memory);
      goto LAB_0040eae5;
    }
  }
  pvVar5 = (void *)0x0;
LAB_0040eae5:
  if (pwVar1 != (wchar_t *)0x0) {
    (*(code *)0x19bb2)(pwVar1);
  }
  return pvVar5;
}



// Library Function - Single Match
//  void * __cdecl try_get_function(enum `anonymous namespace'::function_id,char const * const,enum
// A0x9b56aee1::module_id const * const,enum A0x9b56aee1::module_id const * const)
// 
// Library: Visual Studio 2015 Release

void * __cdecl
try_get_function(function_id param_1,char *param_2,module_id *param_3,module_id *param_4)

{
  uint *puVar1;
  uint uVar2;
  void *pvVar3;
  byte bVar4;
  void *pvVar5;
  
  puVar1 = &DAT_0041b338 + param_1;
  bVar4 = (byte)DAT_0041a208 & 0x1f;
  pvVar5 = (void *)((DAT_0041a208 ^ *puVar1) >> bVar4 | (DAT_0041a208 ^ *puVar1) << 0x20 - bVar4);
  if (pvVar5 != (void *)0xffffffff) {
    if (pvVar5 != (void *)0x0) {
      return pvVar5;
    }
    if (param_3 != param_4) {
      do {
        uVar2 = try_get_module(*param_3);
        if (uVar2 != 0) goto LAB_0040eb51;
        param_3 = param_3 + 1;
      } while (param_3 != param_4);
    }
    uVar2 = 0;
LAB_0040eb51:
    if ((uVar2 != 0) && (pvVar5 = (void *)(*(code *)0x199ba)(uVar2,param_2), pvVar5 != (void *)0x0))
    {
      pvVar3 = __crt_fast_encode_pointer<void*>(pvVar5);
      LOCK();
      *puVar1 = (uint)pvVar3;
      UNLOCK();
      return pvVar5;
    }
    bVar4 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
    LOCK();
    *puVar1 = (0xffffffffU >> bVar4 | -1 << 0x20 - bVar4) ^ DAT_0041a208;
    UNLOCK();
  }
  return (void *)0x0;
}



// Library Function - Multiple Matches With Same Base Name
//  struct HINSTANCE__ * __cdecl try_get_module(enum `anonymous namespace'::module_id)
//  struct HINSTANCE__ * __cdecl try_get_module(enum `anonymous namespace'::module_id)
// 
// Library: Visual Studio 2015 Release

uint __cdecl try_get_module(int param_1)

{
  uint *puVar1;
  uint uVar2;
  undefined *puVar3;
  uint uVar4;
  int iVar5;
  
  puVar1 = &DAT_0041b2e8 + param_1;
  uVar4 = *puVar1;
  if (uVar4 == 0) {
    puVar3 = (&PTR_u_api_ms_win_appmodel_runtime_l1_1_00414f08)[param_1];
    uVar4 = (*(code *)0x199cc)(puVar3,0,0x800);
    if (uVar4 == 0) {
      iVar5 = (*(code *)0x1991a)();
      if (iVar5 == 0x57) {
        uVar4 = (*(code *)0x199cc)(puVar3,0,0);
      }
      else {
        uVar4 = 0;
      }
      if (uVar4 == 0) {
        LOCK();
        *puVar1 = 0xffffffff;
        UNLOCK();
        return 0;
      }
    }
    LOCK();
    uVar2 = *puVar1;
    *puVar1 = uVar4;
    UNLOCK();
    if (uVar2 != 0) {
      (*(code *)0x199ac)(uVar4);
    }
  }
  else {
    uVar4 = -(uint)(uVar4 != 0xffffffff) & uVar4;
  }
  return uVar4;
}



// Library Function - Single Match
//  ___acrt_FlsAlloc@4
// 
// Library: Visual Studio 2015 Release

void ___acrt_FlsAlloc_4(undefined4 param_1)

{
  uint uVar1;
  code *pcVar2;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(3,"FlsAlloc",(module_id *)&DAT_004153a8,
                                    (module_id *)&DAT_004153b0);
  if (pcVar2 == (code *)0x0) {
    (*(code *)0x1997a)();
  }
  else {
    guard_check_icall();
    (*pcVar2)(param_1);
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_FlsFree@4
// 
// Library: Visual Studio 2015 Release

void ___acrt_FlsFree_4(undefined4 param_1)

{
  uint uVar1;
  code *pcVar2;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(4,"FlsFree",(module_id *)&DAT_004153b0,
                                    (module_id *)&DAT_004153b8);
  if (pcVar2 == (code *)0x0) {
    (*(code *)0x199a2)(param_1);
  }
  else {
    guard_check_icall();
    (*pcVar2)();
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_FlsGetValue@4
// 
// Library: Visual Studio 2015 Release

void ___acrt_FlsGetValue_4(undefined4 param_1)

{
  uint uVar1;
  code *pcVar2;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(5,"FlsGetValue",(module_id *)&DAT_004153b8,
                                    (module_id *)&DAT_004153c0);
  if (pcVar2 == (code *)0x0) {
    (*(code *)0x19986)(param_1);
  }
  else {
    guard_check_icall();
    (*pcVar2)();
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_FlsSetValue@8
// 
// Library: Visual Studio 2015 Release

void ___acrt_FlsSetValue_8(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  code *pcVar2;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(6,"FlsSetValue",(module_id *)&DAT_004153c0,
                                    (module_id *)&DAT_004153c8);
  if (pcVar2 == (code *)0x0) {
    (*(code *)0x19994)(param_1,param_2);
  }
  else {
    guard_check_icall();
    (*pcVar2)();
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_InitializeCriticalSectionEx@12
// 
// Library: Visual Studio 2015 Release

void ___acrt_InitializeCriticalSectionEx_12
               (undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  code *pcVar2;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(0x14,"InitializeCriticalSectionEx",(module_id *)&DAT_004153e4,
                                    (module_id *)&DAT_004153ec);
  if (pcVar2 == (code *)0x0) {
    (*(code *)0x19952)(param_1,param_2);
  }
  else {
    guard_check_icall();
    (*pcVar2)(param_1,param_2,param_3);
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_LCMapStringEx@36
// 
// Library: Visual Studio 2015 Release

void ___acrt_LCMapStringEx_36
               (wchar_t *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
               undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
               undefined4 param_9)

{
  uint uVar1;
  code *pcVar2;
  undefined4 uVar3;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(0x16,"LCMapStringEx",(module_id *)&DAT_004153ec,
                                    (module_id *)"LCMapStringEx");
  if (pcVar2 == (code *)0x0) {
    uVar3 = ___acrt_LocaleNameToLCID_8(param_1,0);
    (*(code *)0x19bcc)(uVar3,param_2,param_3,param_4,param_5,param_6);
  }
  else {
    guard_check_icall();
    (*pcVar2)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_LocaleNameToLCID@8
// 
// Library: Visual Studio 2015 Release

void ___acrt_LocaleNameToLCID_8(wchar_t *param_1,undefined4 param_2)

{
  uint uVar1;
  code *pcVar2;
  
  uVar1 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  pcVar2 = (code *)try_get_function(0x18,"LocaleNameToLCID",(module_id *)&DAT_00415404,
                                    (module_id *)"LocaleNameToLCID");
  if (pcVar2 == (code *)0x0) {
    ___acrt_DownlevelLocaleNameToLCID(param_1);
  }
  else {
    guard_check_icall();
    (*pcVar2)(param_1,param_2);
  }
  __security_check_cookie(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_is_packaged_app
// 
// Library: Visual Studio 2015 Release

void __fastcall ___acrt_is_packaged_app(undefined4 param_1)

{
  code *pcVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 local_c;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  local_c = param_1;
  if (DAT_0041b3b8 == 0) {
    pcVar1 = (code *)try_get_function(8,"GetCurrentPackageId",(module_id *)&DAT_004153c8,
                                      (module_id *)"GetCurrentPackageId");
    if (pcVar1 != (code *)0x0) {
      local_c = 0;
      puVar3 = &local_c;
      uVar4 = 0;
      guard_check_icall();
      iVar2 = (*pcVar1)(puVar3,uVar4);
      if (iVar2 == 0x7a) {
        LOCK();
        DAT_0041b3b8 = 1;
        UNLOCK();
        goto LAB_0040ef50;
      }
    }
    LOCK();
    DAT_0041b3b8 = 2;
    UNLOCK();
  }
LAB_0040ef50:
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_uninitialize_winapi_thunks
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined1 __cdecl ___acrt_uninitialize_winapi_thunks(char param_1)

{
  int *piVar1;
  
  if (param_1 == '\0') {
    piVar1 = &DAT_0041b2e8;
    do {
      if (*piVar1 != 0) {
        if (*piVar1 != -1) {
          (*(code *)0x199ac)(*piVar1);
        }
        *piVar1 = 0;
      }
      piVar1 = piVar1 + 1;
    } while (piVar1 != &DAT_0041b338);
  }
  return 1;
}



// Library Function - Single Match
//  ___acrt_lowio_create_handle_array
// 
// Library: Visual Studio 2015 Release

undefined4 * ___acrt_lowio_create_handle_array(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)__calloc_base(0x40,0x30);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else if (puVar2 != puVar2 + 0x300) {
    puVar3 = puVar2 + 8;
    do {
      ___acrt_InitializeCriticalSectionEx_12(puVar3 + -8,4000,0);
      puVar3[-2] = 0xffffffff;
      *puVar3 = 0;
      puVar3[1] = 0;
      puVar1 = puVar3 + 4;
      puVar3[2] = 0xa0a0000;
      *(undefined1 *)(puVar3 + 3) = 10;
      *(byte *)((int)puVar3 + 0xd) = *(byte *)((int)puVar3 + 0xd) & 0xf8;
      *(undefined1 *)((int)puVar3 + 0xe) = 0;
      puVar3 = puVar3 + 0xc;
    } while (puVar1 != puVar2 + 0x300);
  }
  FID_conflict__free((void *)0x0);
  return puVar2;
}



// Library Function - Single Match
//  ___acrt_lowio_destroy_handle_array
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_lowio_destroy_handle_array(void *param_1)

{
  void *pvVar1;
  
  if (param_1 != (void *)0x0) {
    pvVar1 = param_1;
    if (param_1 != (void *)((int)param_1 + 0xc00)) {
      do {
        (*(code *)0x19a2a)(pvVar1);
        pvVar1 = (void *)((int)pvVar1 + 0x30);
      } while (pvVar1 != (void *)((int)param_1 + 0xc00));
    }
    FID_conflict__free(param_1);
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___acrt_lowio_ensure_fh_exists
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl ___acrt_lowio_ensure_fh_exists(uint param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  
  if (param_1 < 0x2000) {
    uVar4 = 0;
    ___acrt_lock(7);
    iVar5 = 0;
    iVar3 = DAT_0041b5c0;
    while (iVar3 <= (int)param_1) {
      if ((&DAT_0041b3c0)[iVar5] == 0) {
        puVar2 = ___acrt_lowio_create_handle_array();
        (&DAT_0041b3c0)[iVar5] = puVar2;
        if (puVar2 == (undefined4 *)0x0) {
          uVar4 = 0xc;
          break;
        }
        iVar3 = DAT_0041b5c0 + 0x40;
        DAT_0041b5c0 = iVar3;
      }
      iVar5 = iVar5 + 1;
    }
    FUN_0040f0d2();
  }
  else {
    piVar1 = __errno();
    uVar4 = 9;
    *piVar1 = 9;
    FUN_0040c975();
  }
  return uVar4;
}



void FUN_0040f0d2(void)

{
  ___acrt_unlock(7);
  return;
}



// Library Function - Single Match
//  ___acrt_lowio_lock_fh
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_lowio_lock_fh(uint param_1)

{
  (*(code *)0x199fa)((param_1 & 0x3f) * 0x30 + (&DAT_0041b3c0)[(int)param_1 >> 6]);
  return;
}



// Library Function - Single Match
//  ___acrt_lowio_unlock_fh
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_lowio_unlock_fh(uint param_1)

{
  (*(code *)0x19a12)((param_1 & 0x3f) * 0x30 + (&DAT_0041b3c0)[(int)param_1 >> 6]);
  return;
}



// Library Function - Single Match
//  __free_osfhnd
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __free_osfhnd(int param_1)

{
  int iVar1;
  int *piVar2;
  ulong *puVar3;
  int iVar4;
  undefined4 uVar5;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0041b5c0)) {
    iVar4 = (param_1 & 0x3fU) * 0x30;
    if (((*(byte *)(iVar4 + 0x28 + (&DAT_0041b3c0)[param_1 >> 6]) & 1) != 0) &&
       (*(int *)(iVar4 + 0x18 + (&DAT_0041b3c0)[param_1 >> 6]) != -1)) {
      iVar1 = FUN_0040b487();
      if (iVar1 == 1) {
        if (param_1 == 0) {
          uVar5 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar5 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0040f187;
          uVar5 = 0xfffffff4;
        }
        (*(code *)0x19bdc)(uVar5,0);
      }
LAB_0040f187:
      *(undefined4 *)(iVar4 + 0x18 + (&DAT_0041b3c0)[param_1 >> 6]) = 0xffffffff;
      return 0;
    }
  }
  piVar2 = __errno();
  *piVar2 = 9;
  puVar3 = ___doserrno();
  *puVar3 = 0;
  return -1;
}



// Library Function - Single Match
//  __get_osfhandle
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b5c0)) {
      iVar3 = (_FileHandle & 0x3fU) * 0x30;
      if ((*(byte *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + iVar3) & 1) != 0) {
        return *(intptr_t *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x18 + iVar3);
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c975();
  }
  return -1;
}



// Library Function - Single Match
//  void __cdecl initialize_inherited_file_handles_nolock(void)
// 
// Library: Visual Studio 2015 Release

void __cdecl initialize_inherited_file_handles_nolock(void)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  undefined1 local_4c [50];
  short local_1a;
  uint *local_18;
  byte *local_8;
  
  (*(code *)0x198b0)(local_4c);
  if ((local_1a != 0) && (local_18 != (uint *)0x0)) {
    uVar3 = *local_18;
    puVar2 = local_18 + 1;
    local_8 = (byte *)((int)puVar2 + uVar3);
    if (0x1fff < (int)uVar3) {
      uVar3 = 0x2000;
    }
    ___acrt_lowio_ensure_fh_exists(uVar3);
    if ((int)DAT_0041b5c0 < (int)uVar3) {
      uVar3 = DAT_0041b5c0;
    }
    uVar4 = 0;
    if (uVar3 != 0) {
      do {
        iVar1 = *(int *)local_8;
        if ((((iVar1 != -1) && (iVar1 != -2)) && ((*puVar2 & 1) != 0)) &&
           (((*puVar2 & 8) != 0 || (iVar1 = (*(code *)0x1974e)(iVar1), iVar1 != 0)))) {
          iVar1 = (uVar4 & 0x3f) * 0x30 + (&DAT_0041b3c0)[(int)uVar4 >> 6];
          *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)local_8;
          *(byte *)(iVar1 + 0x28) = (byte)*puVar2;
        }
        uVar4 = uVar4 + 1;
        local_8 = local_8 + 4;
        puVar2 = (uint *)((int)puVar2 + 1);
      } while (uVar4 != uVar3);
    }
  }
  return;
}



// Library Function - Single Match
//  void __cdecl initialize_stdio_handles_nolock(void)
// 
// Library: Visual Studio 2015 Release

void __cdecl initialize_stdio_handles_nolock(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  
  uVar4 = 0;
  do {
    iVar3 = (uVar4 & 0x3f) * 0x30 + (&DAT_0041b3c0)[(int)uVar4 >> 6];
    if ((*(int *)(iVar3 + 0x18) == -1) || (*(int *)(iVar3 + 0x18) == -2)) {
      *(undefined1 *)(iVar3 + 0x28) = 0x81;
      if (uVar4 == 0) {
        uVar5 = 0xfffffff6;
      }
      else if (uVar4 == 1) {
        uVar5 = 0xfffffff5;
      }
      else {
        uVar5 = 0xfffffff4;
      }
      iVar1 = (*(code *)0x1975c)(uVar5);
      if ((iVar1 == -1) || (iVar1 == 0)) {
        uVar2 = 0;
      }
      else {
        uVar2 = (*(code *)0x1974e)(iVar1);
      }
      if (uVar2 == 0) {
        *(byte *)(iVar3 + 0x28) = *(byte *)(iVar3 + 0x28) | 0x40;
        *(undefined4 *)(iVar3 + 0x18) = 0xfffffffe;
        if (DAT_0041b168 != 0) {
          *(undefined4 *)(*(int *)(DAT_0041b168 + uVar4 * 4) + 0x10) = 0xfffffffe;
        }
      }
      else {
        *(int *)(iVar3 + 0x18) = iVar1;
        if ((uVar2 & 0xff) == 2) {
          *(byte *)(iVar3 + 0x28) = *(byte *)(iVar3 + 0x28) | 0x40;
        }
        else if ((uVar2 & 0xff) == 3) {
          *(byte *)(iVar3 + 0x28) = *(byte *)(iVar3 + 0x28) | 8;
        }
      }
    }
    else {
      *(byte *)(iVar3 + 0x28) = *(byte *)(iVar3 + 0x28) | 0x80;
    }
    uVar4 = uVar4 + 1;
  } while (uVar4 != 3);
  return;
}



void FUN_0040f3d5(void)

{
  ___acrt_unlock(7);
  return;
}



// Library Function - Single Match
//  ___pctype_func
// 
// Library: Visual Studio 2015 Release

ushort * __cdecl ___pctype_func(void)

{
  __acrt_ptd *p_Var1;
  undefined4 *local_8;
  
  p_Var1 = ___acrt_getptd();
  local_8 = *(undefined4 **)(p_Var1 + 0x4c);
  ___acrt_update_locale_info((int)p_Var1,(int *)&local_8);
  return (ushort *)*local_8;
}



// Library Function - Single Match
//  ___acrt_locale_free_monetary
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __cdecl ___acrt_locale_free_monetary(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_0041a92c) {
      FID_conflict__free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_0041a930) {
      FID_conflict__free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_0041a934) {
      FID_conflict__free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_0041a938) {
      FID_conflict__free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_0041a93c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_0041a940) {
      FID_conflict__free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_0041a944) {
      FID_conflict__free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_0041a958) {
      FID_conflict__free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_0041a95c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_0041a960) {
      FID_conflict__free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_0041a964) {
      FID_conflict__free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_0041a968) {
      FID_conflict__free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_0041a96c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x4c));
    }
  }
  return;
}



// Library Function - Single Match
//  ___acrt_locale_free_numeric
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __cdecl ___acrt_locale_free_numeric(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_0041a920) {
      FID_conflict__free((undefined *)*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_0041a924) {
      FID_conflict__free((undefined *)param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_0041a928) {
      FID_conflict__free((undefined *)param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_0041a950) {
      FID_conflict__free((undefined *)param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_0041a954) {
      FID_conflict__free((undefined *)param_1[0xd]);
    }
  }
  return;
}



// Library Function - Single Match
//  void __cdecl free_crt_array_internal(void const * * const,unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl free_crt_array_internal(void **param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  uVar1 = ~-(uint)(param_1 + param_2 < param_1) &
          (uint)((int)(param_1 + param_2) + (3 - (int)param_1)) >> 2;
  if (uVar1 != 0) {
    do {
      FID_conflict__free(*param_1);
      uVar2 = uVar2 + 1;
      param_1 = param_1 + 1;
    } while (uVar2 != uVar1);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_locale_free_time
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_locale_free_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    free_crt_array_internal(param_1,7);
    free_crt_array_internal(param_1 + 7,7);
    free_crt_array_internal(param_1 + 0xe,0xc);
    free_crt_array_internal(param_1 + 0x1a,0xc);
    free_crt_array_internal(param_1 + 0x26,2);
    FID_conflict__free(param_1[0x28]);
    FID_conflict__free(param_1[0x29]);
    FID_conflict__free(param_1[0x2a]);
    free_crt_array_internal(param_1 + 0x2d,7);
    free_crt_array_internal(param_1 + 0x34,7);
    free_crt_array_internal(param_1 + 0x3b,0xc);
    free_crt_array_internal(param_1 + 0x47,0xc);
    free_crt_array_internal(param_1 + 0x53,2);
    FID_conflict__free(param_1[0x55]);
    FID_conflict__free(param_1[0x56]);
    FID_conflict__free(param_1[0x57]);
    FID_conflict__free(param_1[0x58]);
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  ___acrt_GetStringTypeA
// 
// Library: Visual Studio 2015 Release

void __cdecl
___acrt_GetStringTypeA
          (__crt_locale_pointers *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5,int param_6,int param_7)

{
  uint _Size;
  int *_Dst;
  int iVar1;
  int iStack_40;
  int iStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  int local_1c;
  int local_18;
  char local_10;
  int local_c;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  uStack_30 = 0x40f6d7;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,param_1);
  if (param_6 == 0) {
    param_6 = *(int *)(local_18 + 8);
  }
  uStack_30 = 0;
  uStack_34 = param_4;
  uStack_38 = param_3;
  iStack_3c = (uint)(param_7 != 0) * 8 + 1;
  iStack_40 = param_6;
  local_c = (*(code *)0x19a64)();
  if (local_c == 0) goto LAB_0040f7ae;
  _Size = local_c * 2;
  if ((_Size + 8 & -(uint)(_Size < _Size + 8)) == 0) {
    _Dst = (undefined4 *)0x0;
LAB_0040f76f:
    if (_Dst != (undefined4 *)0x0) {
      _memset(_Dst,0,_Size);
      iVar1 = (*(code *)0x19a64)(param_6,1,param_3,param_4,_Dst,local_c);
      if (iVar1 != 0) {
        (*(code *)0x19bec)(param_2,_Dst,iVar1,param_5);
      }
    }
  }
  else if ((-(uint)(_Size < _Size + 8) & _Size + 8) < 0x401) {
    _Dst = &iStack_40;
    if (&stack0x00000000 != (undefined1 *)0x40) {
      iStack_40 = 0xcccc;
      _Dst = &iStack_40;
LAB_0040f768:
      _Dst = _Dst + 2;
      goto LAB_0040f76f;
    }
  }
  else {
    _Dst = (int *)__malloc_base(-(uint)(_Size < _Size + 8) & _Size + 8);
    if (_Dst != (undefined4 *)0x0) {
      *_Dst = 0xdddd;
      goto LAB_0040f768;
    }
  }
  __freea_crt((int)_Dst);
LAB_0040f7ae:
  if (local_10 != '\0') {
    *(uint *)(local_1c + 0x350) = *(uint *)(local_1c + 0x350) & 0xfffffffd;
  }
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __freea_crt
// 
// Library: Visual Studio 2015 Release

void __cdecl __freea_crt(int param_1)

{
  if ((param_1 != 0) && (*(int *)(param_1 + -8) == 0xdddd)) {
    FID_conflict__free((int *)(param_1 + -8));
  }
  return;
}



// Library Function - Single Match
//  ___acrt_add_locale_ref
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_add_locale_ref(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  
  LOCK();
  *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + 1;
  UNLOCK();
  piVar1 = *(int **)(param_1 + 0x7c);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x84);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x80);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x8c);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  puVar2 = (undefined4 *)(param_1 + 0x28);
  iVar3 = 6;
  do {
    if (((undefined *)puVar2[-2] != &DAT_0041a910) &&
       (piVar1 = (int *)*puVar2, piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
      UNLOCK();
    }
    if ((puVar2[-3] != 0) && (piVar1 = (int *)puVar2[-1], piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
      UNLOCK();
    }
    puVar2 = puVar2 + 4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  ___acrt_locale_add_lc_time_reference(*(undefined ***)(param_1 + 0x9c));
  return;
}



// Library Function - Single Match
//  ___acrt_free_locale
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __cdecl ___acrt_free_locale(void *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int local_8;
  
  if ((((*(undefined ***)((int)param_1 + 0x88) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0x88) != &PTR_DAT_0041a920)) &&
      (*(int **)((int)param_1 + 0x7c) != (int *)0x0)) && (**(int **)((int)param_1 + 0x7c) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0x84);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      ___acrt_locale_free_monetary(*(int *)((int)param_1 + 0x88));
    }
    piVar1 = *(int **)((int)param_1 + 0x80);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      ___acrt_locale_free_numeric(*(undefined4 **)((int)param_1 + 0x88));
    }
    FID_conflict__free(*(void **)((int)param_1 + 0x7c));
    FID_conflict__free(*(void **)((int)param_1 + 0x88));
  }
  if ((*(int **)((int)param_1 + 0x8c) != (int *)0x0) && (**(int **)((int)param_1 + 0x8c) == 0)) {
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x90) + -0xfe));
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x94) + -0x80));
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x98) + -0x80));
    FID_conflict__free(*(void **)((int)param_1 + 0x8c));
  }
  ___acrt_locale_free_lc_time_if_unreferenced(*(undefined ***)((int)param_1 + 0x9c));
  puVar2 = (undefined4 *)((int)param_1 + 0xa0);
  local_8 = 6;
  puVar3 = (undefined4 *)((int)param_1 + 0x28);
  do {
    if ((((undefined *)puVar3[-2] != &DAT_0041a910) &&
        (piVar1 = (int *)*puVar3, piVar1 != (int *)0x0)) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      FID_conflict__free((void *)*puVar2);
    }
    if (((puVar3[-3] != 0) && (piVar1 = (int *)puVar3[-1], piVar1 != (int *)0x0)) && (*piVar1 == 0))
    {
      FID_conflict__free(piVar1);
    }
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 4;
    local_8 = local_8 + -1;
  } while (local_8 != 0);
  FID_conflict__free(param_1);
  return;
}



// Library Function - Single Match
//  ___acrt_locale_add_lc_time_reference
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined * __cdecl ___acrt_locale_add_lc_time_reference(undefined **param_1)

{
  undefined **ppuVar1;
  undefined *puVar2;
  
  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_00415d80)) {
    LOCK();
    ppuVar1 = param_1 + 0x2c;
    puVar2 = *ppuVar1;
    *ppuVar1 = *ppuVar1 + 1;
    UNLOCK();
    return puVar2 + 1;
  }
  return (undefined *)0x7fffffff;
}



// Library Function - Single Match
//  ___acrt_locale_free_lc_time_if_unreferenced
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __cdecl ___acrt_locale_free_lc_time_if_unreferenced(undefined **param_1)

{
  if (((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_00415d80)) &&
     (param_1[0x2c] == (undefined *)0x0)) {
    ___acrt_locale_free_time(param_1);
    FID_conflict__free(param_1);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_locale_release_lc_time_reference
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined * __cdecl ___acrt_locale_release_lc_time_reference(undefined **param_1)

{
  undefined **ppuVar1;
  undefined *puVar2;
  
  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_00415d80)) {
    LOCK();
    ppuVar1 = param_1 + 0x2c;
    puVar2 = *ppuVar1;
    *ppuVar1 = *ppuVar1 + -1;
    UNLOCK();
    return puVar2 + -1;
  }
  return (undefined *)0x7fffffff;
}



// Library Function - Single Match
//  ___acrt_release_locale_ref
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_release_locale_ref(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  
  if (param_1 != 0) {
    LOCK();
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + -1;
    UNLOCK();
    piVar1 = *(int **)(param_1 + 0x7c);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x84);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x80);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x8c);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    puVar2 = (undefined4 *)(param_1 + 0x28);
    iVar3 = 6;
    do {
      if (((undefined *)puVar2[-2] != &DAT_0041a910) &&
         (piVar1 = (int *)*puVar2, piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
        UNLOCK();
      }
      if ((puVar2[-3] != 0) && (piVar1 = (int *)puVar2[-1], piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
        UNLOCK();
      }
      puVar2 = puVar2 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    ___acrt_locale_release_lc_time_reference(*(undefined ***)(param_1 + 0x9c));
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___acrt_update_thread_locale_data
// 
// Library: Visual Studio 2015 Release

undefined ** ___acrt_update_thread_locale_data(void)

{
  __acrt_ptd *p_Var1;
  undefined **ppuVar2;
  
  p_Var1 = ___acrt_getptd();
  if (((*(uint *)(p_Var1 + 0x350) & DAT_0041a970) == 0) ||
     (ppuVar2 = *(undefined ***)(p_Var1 + 0x4c), ppuVar2 == (undefined **)0x0)) {
    ___acrt_lock(4);
    ppuVar2 = __updatetlocinfoEx_nolock((undefined4 *)(p_Var1 + 0x4c),DAT_0041b5c4);
    FUN_0040fb24();
    if (ppuVar2 == (undefined **)0x0) {
                    // WARNING: Subroutine does not return
      _abort();
    }
  }
  return ppuVar2;
}



void FUN_0040fb24(void)

{
  ___acrt_unlock(4);
  return;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

undefined ** __cdecl __updatetlocinfoEx_nolock(undefined4 *param_1,undefined **param_2)

{
  undefined **ppuVar1;
  
  if ((param_2 == (undefined **)0x0) || (param_1 == (undefined4 *)0x0)) {
    param_2 = (undefined **)0x0;
  }
  else {
    ppuVar1 = (undefined **)*param_1;
    if (ppuVar1 != param_2) {
      *param_1 = param_2;
      ___acrt_add_locale_ref((int)param_2);
      if (((ppuVar1 != (undefined **)0x0) &&
          (___acrt_release_locale_ref((int)ppuVar1), ppuVar1[3] == (undefined *)0x0)) &&
         (ppuVar1 != &PTR_DAT_0041a850)) {
        ___acrt_free_locale(ppuVar1);
      }
    }
  }
  return param_2;
}



void __cdecl FUN_0040fb85(void *param_1,uint param_2,uint param_3)

{
  __recalloc_base(param_1,param_2,param_3);
  return;
}



// Library Function - Single Match
//  __recalloc_base
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __recalloc_base(void *param_1,uint param_2,uint param_3)

{
  int *piVar1;
  int iVar2;
  size_t sVar3;
  uint uVar4;
  
  if ((param_2 == 0) || (param_3 <= 0xffffffe0 / param_2)) {
    if (param_1 == (void *)0x0) {
      sVar3 = 0;
    }
    else {
      sVar3 = FID_conflict___msize_base(param_1);
    }
    uVar4 = param_2 * param_3;
    iVar2 = __realloc_base(param_1,uVar4);
    if ((iVar2 != 0) && (sVar3 < uVar4)) {
      _memset((void *)(iVar2 + sVar3),0,uVar4 - sVar3);
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0xc;
    iVar2 = 0;
  }
  return iVar2;
}



// Library Function - Single Match
//  ___acrt_execute_initializers
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_execute_initializers(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  code *pcVar2;
  char cVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  
  uVar4 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  puVar5 = param_1;
  if (param_1 != param_2) {
    do {
      pcVar2 = (code *)*puVar5;
      if (pcVar2 != (code *)0x0) {
        guard_check_icall();
        cVar3 = (*pcVar2)();
        if (cVar3 == '\0') break;
      }
      puVar5 = puVar5 + 2;
    } while (puVar5 != param_2);
    if ((puVar5 != param_2) && (puVar5 != param_1)) {
      puVar5 = puVar5 + -1;
      do {
        if ((puVar5[-1] != 0) && (pcVar2 = (code *)*puVar5, pcVar2 != (code *)0x0)) {
          uVar6 = 0;
          guard_check_icall();
          (*pcVar2)(uVar6);
        }
        puVar1 = puVar5 + -1;
        puVar5 = puVar5 + -2;
      } while (puVar1 != param_1);
    }
  }
  __security_check_cookie(uVar4 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_execute_uninitializers
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_execute_uninitializers(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  code *pcVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  
  uVar3 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  if (param_1 != param_2) {
    puVar4 = param_2 + -1;
    do {
      pcVar2 = (code *)*puVar4;
      if (pcVar2 != (code *)0x0) {
        uVar5 = 0;
        guard_check_icall();
        (*pcVar2)(uVar5);
      }
      puVar1 = puVar4 + -1;
      puVar4 = puVar4 + -2;
    } while (puVar1 != param_1);
  }
  __security_check_cookie(uVar3 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Multiple Matches With Same Base Name
//  public: void (__cdecl*__thiscall __crt_seh_guarded_call<void (__cdecl*)(int)>::operator()<class
// <lambda_a048d3beccc847880fc8490e18b82769>,class <lambda_ec61778202f4f5fc7e7711acc23c3bca> &,class
// <lambda_f7496a158712204296dd6628a163878e> >(class <lambda_a048d3beccc847880fc8490e18b82769>
// &&,class <lambda_ec61778202f4f5fc7e7711acc23c3bca> &,class
// <lambda_f7496a158712204296dd6628a163878e> &&))(int)
//  public: void (__cdecl*__thiscall __crt_seh_guarded_call<void (__cdecl*)(int)>::operator()<class
// <lambda_cbab9ec6f41b0180b23cc171c22676b0>,class <lambda_44731a7d0e6d81c3e6aa82d741081786> &,class
// <lambda_4b292cb8dd18144e164572427af410ab> >(class <lambda_cbab9ec6f41b0180b23cc171c22676b0>
// &&,class <lambda_44731a7d0e6d81c3e6aa82d741081786> &,class
// <lambda_4b292cb8dd18144e164572427af410ab> &&))(int)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

uint operator()<>(int *param_1)

{
  byte bVar1;
  uint uVar2;
  
  ___acrt_lock(*param_1);
  bVar1 = (byte)DAT_0041a208 & 0x1f;
  uVar2 = DAT_0041a208 ^ _DAT_0041b5dc;
  FUN_0040fd36();
  return uVar2 >> bVar1 | uVar2 << 0x20 - bVar1;
}



void FUN_0040fd36(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  void (__cdecl*__cdecl __acrt_lock_and_call<class <lambda_ec61778202f4f5fc7e7711acc23c3bca>
// >(enum __acrt_lock_id,class <lambda_ec61778202f4f5fc7e7711acc23c3bca> &&))(int)
// 
// Library: Visual Studio 2015 Release

_func_void_int * __cdecl __acrt_lock_and_call<>(__acrt_lock_id param_1,<> *param_2)

{
  _func_void_int *p_Var1;
  __acrt_lock_id local_10;
  __acrt_lock_id local_c;
  
  local_c = param_1;
  local_10 = param_1;
  p_Var1 = (_func_void_int *)operator()<>((int *)&local_10);
  return p_Var1;
}



// Library Function - Single Match
//  void (__cdecl** __cdecl get_global_action_nolock(int))(int)
// 
// Library: Visual Studio 2015 Release

_func_void_int ** __cdecl get_global_action_nolock(int param_1)

{
  if (param_1 == 2) {
    return (_func_void_int **)&DAT_0041b5d4;
  }
  if (param_1 != 6) {
    if (param_1 == 0xf) {
      return (_func_void_int **)&DAT_0041b5e0;
    }
    if (param_1 == 0x15) {
      return (_func_void_int **)&DAT_0041b5d8;
    }
    if (param_1 != 0x16) {
      return (_func_void_int **)0x0;
    }
  }
  return (_func_void_int **)&DAT_0041b5dc;
}



// Library Function - Single Match
//  struct __crt_signal_action_t * __cdecl siglookup(int,struct __crt_signal_action_t * const)
// 
// Library: Visual Studio 2015 Release

__crt_signal_action_t * __cdecl siglookup(int param_1,__crt_signal_action_t *param_2)

{
  __crt_signal_action_t *p_Var1;
  
  p_Var1 = param_2 + 0x90;
  if (param_2 != p_Var1) {
    do {
      if (*(int *)(param_2 + 4) == param_1) {
        return param_2;
      }
      param_2 = param_2 + 0xc;
    } while (param_2 != p_Var1);
  }
  return (__crt_signal_action_t *)0x0;
}



// Library Function - Single Match
//  ___acrt_get_sigabrt_handler
// 
// Library: Visual Studio 2015 Release

void ___acrt_get_sigabrt_handler(void)

{
  <> local_5;
  
  __acrt_lock_and_call<>(3,&local_5);
  return;
}



// Library Function - Single Match
//  ___acrt_initialize_signal_handlers
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_initialize_signal_handlers(_func_void_int *param_1)

{
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b5d4,param_1);
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b5d8,param_1);
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b5dc,param_1);
  __crt_state_management::dual_state_global<>::initialize
            ((dual_state_global<> *)&DAT_0041b5e0,param_1);
  return;
}



int FUN_0040fe26(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = ___acrt_getptd();
  return (int)(p_Var1 + 8);
}



// WARNING: Function: __SEH_prolog4_GS replaced with injection: SEH_prolog4
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2015 Release

int __cdecl _raise(int _SigNum)

{
  __crt_signal_action_t *p_Var1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  char extraout_CL;
  char cVar5;
  byte bVar6;
  _func_void_int *p_Var7;
  __acrt_ptd *p_Var8;
  int iVar9;
  undefined4 local_38;
  int local_34;
  char local_21;
  
  p_Var8 = (__acrt_ptd *)0x0;
  local_38 = 0;
  local_21 = '\x01';
  if (8 < _SigNum) {
    if (_SigNum == 0xb) goto LAB_0040fe89;
    if ((_SigNum == 0xf) || ((0x14 < _SigNum && (_SigNum < 0x17)))) goto LAB_0040fe7e;
LAB_0040feb4:
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_0040c975();
    goto LAB_00410031;
  }
  if (_SigNum == 8) {
LAB_0040fe89:
    p_Var8 = ___acrt_getptd_noexit();
    if (p_Var8 == (__acrt_ptd *)0x0) goto LAB_00410031;
    p_Var1 = siglookup(_SigNum,*(__crt_signal_action_t **)p_Var8);
    if (p_Var1 == (__crt_signal_action_t *)0x0) goto LAB_0040feb4;
    p_Var1 = p_Var1 + 8;
    cVar5 = '\0';
    local_21 = '\0';
  }
  else {
    if (_SigNum != 2) {
      if (_SigNum == 4) goto LAB_0040fe89;
      if (_SigNum != 6) goto LAB_0040feb4;
    }
LAB_0040fe7e:
    p_Var1 = (__crt_signal_action_t *)get_global_action_nolock(_SigNum);
    cVar5 = extraout_CL;
  }
  local_34 = 0;
  if (cVar5 != '\0') {
    ___acrt_lock(3);
    cVar5 = local_21;
  }
  if (cVar5 == '\0') {
    p_Var7 = *(_func_void_int **)p_Var1;
    local_21 = '\0';
  }
  else {
    bVar6 = (byte)DAT_0041a208 & 0x1f;
    p_Var7 = (_func_void_int *)
             ((DAT_0041a208 ^ (uint)*(_func_void_int **)p_Var1) >> bVar6 |
             (DAT_0041a208 ^ (uint)*(_func_void_int **)p_Var1) << 0x20 - bVar6);
  }
  if (p_Var7 != (_func_void_int *)0x1) {
    if (p_Var7 == (_func_void_int *)0x0) {
      if (local_21 != '\0') {
        ___acrt_unlock(3);
      }
                    // WARNING: Subroutine does not return
      __exit(3);
    }
    if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
      local_34 = *(int *)(p_Var8 + 4);
      *(int *)(p_Var8 + 4) = 0;
      if (_SigNum == 8) {
        puVar3 = (undefined4 *)FUN_0040fe26();
        local_38 = *puVar3;
        puVar3 = (undefined4 *)FUN_0040fe26();
        *puVar3 = 0x8c;
        goto LAB_0040ff70;
      }
    }
    else {
LAB_0040ff70:
      if (_SigNum == 8) {
        iVar9 = *(int *)p_Var8;
        for (iVar4 = iVar9 + 0x24; iVar4 != iVar9 + 0x90; iVar4 = iVar4 + 0xc) {
          *(undefined4 *)(iVar4 + 8) = 0;
        }
        goto LAB_0040ffb2;
      }
    }
    bVar6 = 0x20 - ((byte)DAT_0041a208 & 0x1f) & 0x1f;
    *(_func_void_int **)p_Var1 =
         (_func_void_int *)((0U >> bVar6 | 0 << 0x20 - bVar6) ^ DAT_0041a208);
  }
LAB_0040ffb2:
  FUN_0040ffef();
  if (p_Var7 != (_func_void_int *)0x1) {
    if (_SigNum == 8) {
      ___acrt_getptd();
      iVar9 = 8;
      guard_check_icall();
      (*p_Var7)(iVar9);
    }
    else {
      iVar9 = _SigNum;
      guard_check_icall();
      (*p_Var7)(iVar9);
      if ((_SigNum != 0xb) && (_SigNum != 4)) goto LAB_00410031;
    }
    *(int *)(p_Var8 + 4) = local_34;
    if (_SigNum == 8) {
      p_Var8 = ___acrt_getptd();
      *(undefined4 *)(p_Var8 + 8) = local_38;
    }
  }
LAB_00410031:
  iVar9 = FUN_00412f89();
  return iVar9;
}



void FUN_0040ffef(void)

{
  int unaff_EBP;
  
  if (*(char *)(unaff_EBP + -0x1d) != '\0') {
    ___acrt_unlock(3);
  }
  return;
}



// Library Function - Single Match
//  ___hw_cw_sse2
// 
// Library: Visual Studio 2015 Release

uint __cdecl ___hw_cw_sse2(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = 0;
  if ((param_1 & 0x10) != 0) {
    uVar1 = 0x80;
  }
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 0x400;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x800;
  }
  if ((param_1 & 1) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  if ((param_1 & 0x80000) != 0) {
    uVar1 = uVar1 | 0x100;
  }
  uVar2 = param_1 & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x2000;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x4000;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0x6000;
    }
  }
  uVar2 = param_1 & 0x3000000;
  if (uVar2 == 0x1000000) {
    uVar1 = uVar1 | 0x8040;
  }
  else {
    if (uVar2 == 0x2000000) {
      return uVar1 | 0x40;
    }
    if (uVar2 == 0x3000000) {
      return uVar1 | 0x8000;
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __control87
// 
// Library: Visual Studio 2015 Release

uint __cdecl __control87(uint _NewValue,uint _Mask)

{
  uint uVar1;
  uint uVar2;
  ushort uVar3;
  uint uVar4;
  ushort in_FPUControlWord;
  
  uVar1 = 0;
  if ((in_FPUControlWord & 1) != 0) {
    uVar1 = 0x10;
  }
  if ((in_FPUControlWord & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((in_FPUControlWord & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((in_FPUControlWord & 0x10) != 0) {
    uVar1 = uVar1 | 2;
  }
  if ((in_FPUControlWord & 0x20) != 0) {
    uVar1 = uVar1 | 1;
  }
  if ((in_FPUControlWord & 2) != 0) {
    uVar1 = uVar1 | 0x80000;
  }
  uVar3 = in_FPUControlWord & 0xc00;
  if ((in_FPUControlWord & 0xc00) != 0) {
    if (uVar3 == 0x400) {
      uVar1 = uVar1 | 0x100;
    }
    else if (uVar3 == 0x800) {
      uVar1 = uVar1 | 0x200;
    }
    else if (uVar3 == 0xc00) {
      uVar1 = uVar1 | 0x300;
    }
  }
  if ((in_FPUControlWord & 0x300) == 0) {
    uVar1 = uVar1 | 0x20000;
  }
  else if ((in_FPUControlWord & 0x300) == 0x200) {
    uVar1 = uVar1 | 0x10000;
  }
  if ((in_FPUControlWord & 0x1000) != 0) {
    uVar1 = uVar1 | 0x40000;
  }
  uVar4 = ~_Mask & uVar1 | _NewValue & _Mask;
  if (uVar4 != uVar1) {
    uVar1 = __hw_cw(uVar4);
    uVar4 = 0;
    if ((uVar1 & 1) != 0) {
      uVar4 = 0x10;
    }
    if ((uVar1 & 4) != 0) {
      uVar4 = uVar4 | 8;
    }
    if ((uVar1 & 8) != 0) {
      uVar4 = uVar4 | 4;
    }
    if ((uVar1 & 0x10) != 0) {
      uVar4 = uVar4 | 2;
    }
    if ((uVar1 & 0x20) != 0) {
      uVar4 = uVar4 | 1;
    }
    if ((uVar1 & 2) != 0) {
      uVar4 = uVar4 | 0x80000;
    }
    uVar2 = uVar1 & 0xc00;
    if ((uVar1 & 0xc00) != 0) {
      if (uVar2 == 0x400) {
        uVar4 = uVar4 | 0x100;
      }
      else if (uVar2 == 0x800) {
        uVar4 = uVar4 | 0x200;
      }
      else if (uVar2 == 0xc00) {
        uVar4 = uVar4 | 0x300;
      }
    }
    if ((uVar1 & 0x300) == 0) {
      uVar4 = uVar4 | 0x20000;
    }
    else if ((uVar1 & 0x300) == 0x200) {
      uVar4 = uVar4 | 0x10000;
    }
    if ((uVar1 & 0x1000) != 0) {
      uVar4 = uVar4 | 0x40000;
    }
  }
  uVar1 = uVar4;
  if (0 < DAT_0041ac24) {
    uVar2 = 0;
    if ((char)MXCSR < '\0') {
      uVar2 = 0x10;
    }
    if ((MXCSR & 0x200) != 0) {
      uVar2 = uVar2 | 8;
    }
    if ((MXCSR & 0x400) != 0) {
      uVar2 = uVar2 | 4;
    }
    if ((MXCSR & 0x800) != 0) {
      uVar2 = uVar2 | 2;
    }
    if ((MXCSR & 0x1000) != 0) {
      uVar2 = uVar2 | 1;
    }
    if ((MXCSR & 0x100) != 0) {
      uVar2 = uVar2 | 0x80000;
    }
    uVar1 = MXCSR & 0x6000;
    if (uVar1 != 0) {
      if (uVar1 == 0x2000) {
        uVar2 = uVar2 | 0x100;
      }
      else if (uVar1 == 0x4000) {
        uVar2 = uVar2 | 0x200;
      }
      else if (uVar1 == 0x6000) {
        uVar2 = uVar2 | 0x300;
      }
    }
    uVar1 = MXCSR & 0x8040;
    if (uVar1 == 0x40) {
      uVar2 = uVar2 | 0x2000000;
    }
    else if (uVar1 == 0x8000) {
      uVar2 = uVar2 | 0x3000000;
    }
    else if (uVar1 == 0x8040) {
      uVar2 = uVar2 | 0x1000000;
    }
    uVar1 = ~(_Mask & 0x308031f) & uVar2 | _Mask & 0x308031f & _NewValue;
    if (uVar1 != uVar2) {
      uVar1 = ___hw_cw_sse2(uVar1);
      ___set_fpsr_sse2(uVar1);
      uVar2 = 0;
      if ((char)MXCSR < '\0') {
        uVar2 = 0x10;
      }
      if ((MXCSR & 0x200) != 0) {
        uVar2 = uVar2 | 8;
      }
      if ((MXCSR & 0x400) != 0) {
        uVar2 = uVar2 | 4;
      }
      if ((MXCSR & 0x800) != 0) {
        uVar2 = uVar2 | 2;
      }
      if ((MXCSR & 0x1000) != 0) {
        uVar2 = uVar2 | 1;
      }
      if ((MXCSR & 0x100) != 0) {
        uVar2 = uVar2 | 0x80000;
      }
      uVar1 = MXCSR & 0x6000;
      if (uVar1 != 0) {
        if (uVar1 == 0x2000) {
          uVar2 = uVar2 | 0x100;
        }
        else if (uVar1 == 0x4000) {
          uVar2 = uVar2 | 0x200;
        }
        else if (uVar1 == 0x6000) {
          uVar2 = uVar2 | 0x300;
        }
      }
      uVar1 = MXCSR & 0x8040;
      if (uVar1 == 0x40) {
        uVar2 = uVar2 | 0x2000000;
      }
      else if (uVar1 == 0x8000) {
        uVar2 = uVar2 | 0x3000000;
      }
      else if (uVar1 == 0x8040) {
        uVar2 = uVar2 | 0x1000000;
      }
    }
    uVar1 = uVar2 | uVar4;
    if (((uVar2 ^ uVar4) & 0x8031f) != 0) {
      uVar1 = uVar1 | 0x80000000;
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __hw_cw
// 
// Library: Visual Studio 2015 Release

uint __cdecl __hw_cw(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = (uint)((param_1 & 0x10) != 0);
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x10;
  }
  if ((param_1 & 1) != 0) {
    uVar1 = uVar1 | 0x20;
  }
  if ((param_1 & 0x80000) != 0) {
    uVar1 = uVar1 | 2;
  }
  uVar2 = param_1 & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x400;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x800;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0xc00;
    }
  }
  if ((param_1 & 0x30000) == 0) {
    uVar1 = uVar1 | 0x300;
  }
  else if ((param_1 & 0x30000) == 0x10000) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_1 & 0x40000) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  return uVar1;
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2015 Release

int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  int local_14;
  localeinfo_struct local_10;
  char local_8;
  
  if ((_SrcCh == (char *)0x0) || (_SrcSizeInBytes == 0)) {
    return 0;
  }
  if (*_SrcCh == '\0') {
    if (_DstCh == (wchar_t *)0x0) {
      return 0;
    }
    *_DstCh = L'\0';
    return 0;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,(__crt_locale_pointers *)_Locale);
  if ((local_10.locinfo)->locale_name[2] == (wchar_t *)0x0) {
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = (ushort)(byte)*_SrcCh;
    }
    uVar3 = 1;
    goto LAB_0041055f;
  }
  iVar1 = __isleadbyte_l((uint)(byte)*_SrcCh,&local_10);
  if (iVar1 == 0) {
    uVar3 = 1;
    iVar1 = (*(code *)0x19a64)((local_10.locinfo)->lc_collate_cp,9,_SrcCh,1,_DstCh,
                               _DstCh != (wchar_t *)0x0);
    if (iVar1 != 0) goto LAB_0041055f;
LAB_00410551:
    piVar2 = __errno();
    uVar3 = 0xffffffff;
    *piVar2 = 0x2a;
  }
  else {
    if ((int)(local_10.locinfo)->lc_codepage < 2) {
LAB_0041051e:
      uVar3 = (local_10.locinfo)->lc_codepage;
LAB_00410521:
      if ((_SrcSizeInBytes < uVar3) || (_SrcCh[1] == '\0')) goto LAB_00410551;
    }
    else {
      uVar3 = (local_10.locinfo)->lc_codepage;
      if ((int)_SrcSizeInBytes < (int)uVar3) goto LAB_00410521;
      iVar1 = (*(code *)0x19a64)((local_10.locinfo)->lc_collate_cp,9,_SrcCh,
                                 (local_10.locinfo)->lc_codepage,_DstCh,_DstCh != (wchar_t *)0x0);
      if (iVar1 == 0) goto LAB_0041051e;
    }
    uVar3 = (local_10.locinfo)->lc_codepage;
  }
LAB_0041055f:
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
    return uVar3;
  }
  return uVar3;
}



// Library Function - Single Match
//  _mbtowc
// 
// Library: Visual Studio 2015 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  ___acrt_update_locale_info
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_update_locale_info(int param_1,int *param_2)

{
  undefined **ppuVar1;
  
  if ((*param_2 != DAT_0041b5c4) && ((*(uint *)(param_1 + 0x350) & DAT_0041a970) == 0)) {
    ppuVar1 = ___acrt_update_thread_locale_data();
    *param_2 = (int)ppuVar1;
  }
  return;
}



// Library Function - Single Match
//  ___acrt_update_multibyte_info
// 
// Library: Visual Studio 2015 Release

void __cdecl ___acrt_update_multibyte_info(int param_1,int *param_2)

{
  int *piVar1;
  
  if (((undefined *)*param_2 != PTR_DAT_0041a848) &&
     ((*(uint *)(param_1 + 0x350) & DAT_0041a970) == 0)) {
    piVar1 = ___acrt_update_thread_multibyte_data();
    *param_2 = (int)piVar1;
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __fcloseall
// 
// Library: Visual Studio 2015 Release

int __cdecl __fcloseall(void)

{
  int iVar1;
  int iVar2;
  undefined4 local_20;
  
  local_20 = 0;
  ___acrt_lock(8);
  for (iVar2 = 3; iVar2 != DAT_0041b164; iVar2 = iVar2 + 1) {
    iVar1 = *(int *)(DAT_0041b168 + iVar2 * 4);
    if (iVar1 != 0) {
      if ((*(uint *)(iVar1 + 0xc) >> 0xd & 1) != 0) {
        iVar1 = _fclose(*(FILE **)(DAT_0041b168 + iVar2 * 4));
        if (iVar1 != -1) {
          local_20 = local_20 + 1;
        }
      }
      (*(code *)0x19a2a)(*(int *)(DAT_0041b168 + iVar2 * 4) + 0x20);
      FID_conflict__free(*(void **)(DAT_0041b168 + iVar2 * 4));
      *(undefined4 *)(DAT_0041b168 + iVar2 * 4) = 0;
    }
  }
  FUN_00410682();
  return local_20;
}



void FUN_00410682(void)

{
  ___acrt_unlock(8);
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 2015 Release

int __cdecl __isatty(int _FileHandle)

{
  int *piVar1;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b5c0)) {
      return *(byte *)((&DAT_0041b3c0)[_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3fU) * 0x30) &
             0x40;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_0040c975();
  }
  return 0;
}



// Library Function - Single Match
//  __int64 __cdecl common_lseek_nolock<__int64>(int,__int64,int)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

__int64 __cdecl common_lseek_nolock<__int64>(int param_1,__int64 param_2,int param_3)

{
  byte *pbVar1;
  intptr_t iVar2;
  int *piVar3;
  int iVar4;
  ulong uVar5;
  undefined4 in_stack_00000008;
  uint local_c;
  uint local_8;
  
  iVar2 = __get_osfhandle(param_1);
  if (iVar2 == -1) {
    piVar3 = __errno();
    *piVar3 = 9;
  }
  else {
    iVar4 = (*(code *)0x19c10)(iVar2,in_stack_00000008,(undefined4)param_2,&local_c,param_2._4_4_);
    if (iVar4 == 0) {
      uVar5 = (*(code *)0x1991a)();
      ___acrt_errno_map_os_error(uVar5);
    }
    else if ((local_c & local_8) != 0xffffffff) {
      pbVar1 = (byte *)((&DAT_0041b3c0)[param_1 >> 6] + 0x28 + (param_1 & 0x3fU) * 0x30);
      *pbVar1 = *pbVar1 & 0xfd;
      goto LAB_00410759;
    }
  }
  local_c = 0xffffffff;
  local_8 = 0xffffffff;
LAB_00410759:
  return CONCAT44(local_8,local_c);
}



// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2015 Release

longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  int unaff_EBP;
  __int64 _Var1;
  
  _Var1 = common_lseek_nolock<__int64>(_FileHandle,_Offset,unaff_EBP);
  return _Var1;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2015 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  int iVar1;
  undefined1 local_8 [4];
  
  if (DAT_0041a984 == -2) {
    ___dcrt_lowio_initialize_console_output();
  }
  if ((DAT_0041a984 == -1) ||
     (iVar1 = (*(code *)0x19c24)(DAT_0041a984,&_WCh,1,local_8,0), iVar1 == 0)) {
    _WCh = L'\xffff';
  }
  return _WCh;
}



// Library Function - Single Match
//  void __cdecl shortsort(char *,char *,unsigned int,int (__cdecl*)(void const *,void const *))
// 
// Library: Visual Studio 2015 Release

void __cdecl
shortsort(char *param_1,char *param_2,uint param_3,_func_int_void_ptr_void_ptr *param_4)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  
  uVar2 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  if (param_1 < param_2) {
    do {
      pcVar6 = param_1;
      for (pcVar4 = param_1 + param_3; pcVar4 <= param_2; pcVar4 = pcVar4 + param_3) {
        pcVar7 = pcVar4;
        pcVar8 = pcVar6;
        guard_check_icall();
        iVar3 = (*param_4)(pcVar7,pcVar8);
        if (0 < iVar3) {
          pcVar6 = pcVar4;
        }
      }
      if ((pcVar6 != param_2) && (pcVar4 = param_2, uVar5 = param_3, param_3 != 0)) {
        do {
          pcVar7 = pcVar4 + 1;
          cVar1 = pcVar7[(int)(pcVar6 + (-1 - (int)param_2))];
          pcVar7[(int)(pcVar6 + (-1 - (int)param_2))] = *pcVar4;
          *pcVar4 = cVar1;
          uVar5 = uVar5 - 1;
          pcVar4 = pcVar7;
        } while (uVar5 != 0);
      }
      param_2 = param_2 + -param_3;
    } while (param_1 < param_2);
  }
  __security_check_cookie(uVar2 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  void __cdecl swap(char *,char *,unsigned int)
// 
// Library: Visual Studio 2015 Release

void __cdecl swap(char *param_1,char *param_2,uint param_3)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  
  if ((param_1 != param_2) && (pcVar3 = param_2, param_3 != 0)) {
    do {
      pcVar1 = pcVar3 + 1;
      cVar2 = pcVar1[(int)(param_1 + (-1 - (int)param_2))];
      pcVar1[(int)(param_1 + (-1 - (int)param_2))] = *pcVar3;
      *pcVar3 = cVar2;
      param_3 = param_3 - 1;
      pcVar3 = pcVar1;
    } while (param_3 != 0);
  }
  return;
}



// Library Function - Single Match
//  _qsort
// 
// Library: Visual Studio 2015 Release

void __cdecl
_qsort(void *_Base,size_t _NumOfElements,size_t _SizeOfElements,_PtFuncCompare *_PtFuncCompare)

{
  uint uVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  size_t sVar8;
  char *pcVar9;
  char *pcVar10;
  char *local_114;
  char *local_110;
  int local_10c;
  char *local_108;
  undefined4 auStack_f8 [30];
  undefined4 auStack_80 [30];
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  local_108 = (char *)_Base;
  if ((((_Base == (void *)0x0) && (_NumOfElements != 0)) || (_SizeOfElements == 0)) ||
     (_PtFuncCompare == (_PtFuncCompare *)0x0)) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_0040c975();
    __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  local_10c = 0;
  if (_NumOfElements < 2) {
LAB_00410c2a:
    __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  pcVar5 = (char *)((_NumOfElements - 1) * _SizeOfElements + (int)_Base);
LAB_00410925:
  while (uVar1 = (uint)((int)pcVar5 - (int)local_108) / _SizeOfElements + 1, 8 < uVar1) {
    pcVar7 = local_108 + (uVar1 >> 1) * _SizeOfElements;
    pcVar9 = local_108;
    pcVar6 = pcVar7;
    guard_check_icall();
    iVar4 = (*_PtFuncCompare)(pcVar9,pcVar6);
    if (0 < iVar4) {
      swap(local_108,pcVar7,_SizeOfElements);
    }
    pcVar9 = local_108;
    pcVar6 = pcVar5;
    guard_check_icall();
    iVar4 = (*_PtFuncCompare)(pcVar9,pcVar6);
    if (0 < iVar4) {
      swap(local_108,pcVar5,_SizeOfElements);
    }
    pcVar9 = pcVar7;
    pcVar6 = pcVar5;
    guard_check_icall();
    iVar4 = (*_PtFuncCompare)(pcVar9,pcVar6);
    local_110 = local_108;
    pcVar9 = pcVar5;
    local_114 = pcVar7;
    if (0 < iVar4) {
      swap(pcVar7,pcVar5,_SizeOfElements);
    }
LAB_004109f0:
    pcVar6 = pcVar9;
    if (local_110 < pcVar7) {
      do {
        local_110 = local_110 + _SizeOfElements;
        if (pcVar7 <= local_110) goto LAB_00410a31;
        pcVar10 = local_110;
        pcVar6 = pcVar7;
        guard_check_icall();
        iVar4 = (*_PtFuncCompare)(pcVar10,pcVar6);
      } while (iVar4 < 1);
      if (pcVar7 <= local_110) goto LAB_00410a31;
    }
    else {
LAB_00410a31:
      do {
        pcVar9 = pcVar6;
        local_110 = local_110 + _SizeOfElements;
        if (pcVar5 < local_110) break;
        pcVar6 = local_110;
        pcVar9 = pcVar7;
        guard_check_icall();
        iVar4 = (*_PtFuncCompare)(pcVar6,pcVar9);
        pcVar6 = pcVar9;
      } while (iVar4 < 1);
    }
    do {
      pcVar9 = pcVar9 + -_SizeOfElements;
      if (pcVar9 <= pcVar7) break;
      pcVar6 = pcVar9;
      pcVar10 = pcVar7;
      guard_check_icall();
      iVar4 = (*_PtFuncCompare)(pcVar6,pcVar10);
    } while (0 < iVar4);
    if (local_110 <= pcVar9) {
      pcVar6 = pcVar9;
      sVar8 = _SizeOfElements;
      if (local_110 != pcVar9) {
        do {
          pcVar7 = pcVar6 + 1;
          cVar2 = pcVar7[(int)(local_110 + (-1 - (int)pcVar9))];
          pcVar7[(int)(local_110 + (-1 - (int)pcVar9))] = *pcVar6;
          *pcVar6 = cVar2;
          sVar8 = sVar8 - 1;
          pcVar6 = pcVar7;
          pcVar7 = local_114;
        } while (sVar8 != 0);
      }
      if (pcVar7 == pcVar9) {
        local_114 = local_110;
        pcVar7 = local_110;
      }
      goto LAB_004109f0;
    }
    pcVar9 = pcVar9 + _SizeOfElements;
    if (pcVar7 < pcVar9) {
      do {
        pcVar9 = pcVar9 + -_SizeOfElements;
        if (pcVar9 <= pcVar7) goto LAB_00410b41;
        pcVar6 = pcVar9;
        pcVar10 = pcVar7;
        guard_check_icall();
        iVar4 = (*_PtFuncCompare)(pcVar6,pcVar10);
      } while (iVar4 == 0);
      if (pcVar9 <= pcVar7) goto LAB_00410b41;
    }
    else {
LAB_00410b41:
      do {
        pcVar9 = pcVar9 + -_SizeOfElements;
        if (pcVar9 <= local_108) break;
        pcVar6 = pcVar9;
        pcVar10 = pcVar7;
        guard_check_icall();
        iVar4 = (*_PtFuncCompare)(pcVar6,pcVar10);
      } while (iVar4 == 0);
    }
    if ((int)pcVar9 - (int)local_108 < (int)pcVar5 - (int)local_110) goto LAB_00410bbb;
    if (local_108 < pcVar9) {
      auStack_f8[local_10c] = local_108;
      auStack_80[local_10c] = pcVar9;
      local_10c = local_10c + 1;
    }
    local_108 = local_110;
    if (pcVar5 <= local_110) goto LAB_00410c02;
  }
  shortsort(local_108,pcVar5,_SizeOfElements,(_func_int_void_ptr_void_ptr *)_PtFuncCompare);
  goto LAB_00410c02;
LAB_00410bbb:
  if (local_110 < pcVar5) {
    auStack_f8[local_10c] = local_110;
    auStack_80[local_10c] = pcVar5;
    local_10c = local_10c + 1;
  }
  pcVar5 = pcVar9;
  if (pcVar9 <= local_108) {
LAB_00410c02:
    local_10c = local_10c + -1;
    if (-1 < local_10c) {
      local_108 = (char *)auStack_f8[local_10c];
      pcVar5 = (char *)auStack_80[local_10c];
      goto LAB_00410925;
    }
    goto LAB_00410c2a;
  }
  goto LAB_00410925;
}



// Library Function - Single Match
//  int __cdecl common_tcsncpy_s<char>(char * const,unsigned int,char const * const,unsigned int)
// 
// Library: Visual Studio 2015 Release

int __cdecl common_tcsncpy_s<char>(char *param_1,uint param_2,char *param_3,uint param_4)

{
  char cVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  
  if (param_4 == 0) {
    if (param_1 == (char *)0x0) {
      if (param_2 == 0) {
        return 0;
      }
    }
    else {
LAB_00410c5c:
      if (param_2 != 0) {
        if (param_4 == 0) {
          *param_1 = '\0';
          return 0;
        }
        if (param_3 != (char *)0x0) {
          uVar3 = param_4;
          uVar4 = param_2;
          pcVar5 = param_1;
          if (param_4 == 0xffffffff) {
            do {
              cVar1 = pcVar5[(int)param_3 - (int)param_1];
              *pcVar5 = cVar1;
              pcVar5 = pcVar5 + 1;
              if (cVar1 == '\0') break;
              uVar4 = uVar4 - 1;
            } while (uVar4 != 0);
          }
          else {
            do {
              cVar1 = pcVar5[(int)param_3 - (int)param_1];
              *pcVar5 = cVar1;
              pcVar5 = pcVar5 + 1;
              if ((cVar1 == '\0') || (uVar4 = uVar4 - 1, uVar4 == 0)) break;
              uVar3 = uVar3 - 1;
            } while (uVar3 != 0);
            if (uVar3 == 0) {
              *pcVar5 = '\0';
            }
          }
          if (uVar4 != 0) {
            return 0;
          }
          if (param_4 == 0xffffffff) {
            param_1[param_2 - 1] = '\0';
            return 0x50;
          }
          *param_1 = '\0';
          piVar2 = __errno();
          iVar6 = 0x22;
          goto LAB_00410c7c;
        }
        *param_1 = '\0';
      }
    }
  }
  else if (param_1 != (char *)0x0) goto LAB_00410c5c;
  piVar2 = __errno();
  iVar6 = 0x16;
LAB_00410c7c:
  *piVar2 = iVar6;
  FUN_0040c975();
  return iVar6;
}



void __cdecl FUN_00410ceb(char *param_1,uint param_2,char *param_3,uint param_4)

{
  common_tcsncpy_s<char>(param_1,param_2,param_3,param_4);
  return;
}



// Library Function - Single Match
//  _strpbrk
// 
// Library: Visual Studio

char * __cdecl _strpbrk(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  byte abStack_28 [32];
  
  abStack_28[0x1c] = 0;
  abStack_28[0x1d] = 0;
  abStack_28[0x1e] = 0;
  abStack_28[0x1f] = 0;
  abStack_28[0x18] = 0;
  abStack_28[0x19] = 0;
  abStack_28[0x1a] = 0;
  abStack_28[0x1b] = 0;
  abStack_28[0x14] = 0;
  abStack_28[0x15] = 0;
  abStack_28[0x16] = 0;
  abStack_28[0x17] = 0;
  abStack_28[0x10] = 0;
  abStack_28[0x11] = 0;
  abStack_28[0x12] = 0;
  abStack_28[0x13] = 0;
  abStack_28[0xc] = 0;
  abStack_28[0xd] = 0;
  abStack_28[0xe] = 0;
  abStack_28[0xf] = 0;
  abStack_28[8] = 0;
  abStack_28[9] = 0;
  abStack_28[10] = 0;
  abStack_28[0xb] = 0;
  abStack_28[4] = 0;
  abStack_28[5] = 0;
  abStack_28[6] = 0;
  abStack_28[7] = 0;
  abStack_28[0] = 0;
  abStack_28[1] = 0;
  abStack_28[2] = 0;
  abStack_28[3] = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    abStack_28[(int)(uint)bVar1 >> 3] = abStack_28[(int)(uint)bVar1 >> 3] | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((abStack_28[(int)(uint)bVar1 >> 3] >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



// Library Function - Single Match
//  __mbsdec
// 
// Library: Visual Studio 2015 Release

uchar * __cdecl __mbsdec(uchar *_Start,uchar *_Pos)

{
  uchar *puVar1;
  
  puVar1 = __mbsdec_l(_Start,_Pos,(_locale_t)0x0);
  return puVar1;
}



// Library Function - Single Match
//  __mbsdec_l
// 
// Library: Visual Studio 2015 Release

uchar * __cdecl __mbsdec_l(uchar *_Start,uchar *_Pos,_locale_t _Locale)

{
  int *piVar1;
  byte *pbVar2;
  int local_14 [2];
  int local_c;
  char local_8;
  
  if (_Start == (uchar *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
  }
  else if (_Pos == (uchar *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
  }
  else if (_Start < _Pos) {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(__crt_locale_pointers *)_Locale);
    if (*(int *)(local_c + 8) != 0) {
      pbVar2 = _Pos + -1;
      do {
        pbVar2 = pbVar2 + -1;
        if (pbVar2 < _Start) break;
      } while ((*(byte *)(*pbVar2 + 0x19 + local_c) & 4) != 0);
      _Pos = _Pos + -((int)_Pos - (int)pbVar2 & 1U);
    }
    if (local_8 != '\0') {
      *(uint *)(local_14[0] + 0x350) = *(uint *)(local_14[0] + 0x350) & 0xfffffffd;
      return _Pos + -1;
    }
    return _Pos + -1;
  }
  return (uchar *)0x0;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __acrt_LCMapStringA_stat(struct __crt_locale_pointers *,wchar_t const *,unsigned
// long,char const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2015 Release

int __cdecl
__acrt_LCMapStringA_stat
          (__crt_locale_pointers *param_1,wchar_t *param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  int iStack_30;
  int iStack_2c;
  char *pcStack_28;
  int iStack_24;
  
  uVar2 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  iVar5 = param_5;
  if (0 < param_5) {
    iStack_24 = 0x410e17;
    iVar3 = ___strncnt(param_4,param_5);
    iVar5 = iVar3 + 1;
    if (param_5 <= iVar3) {
      iVar5 = iVar3;
    }
  }
  if (param_8 == 0) {
    param_8 = *(int *)(*(int *)param_1 + 8);
  }
  pcStack_28 = param_4;
  iStack_2c = (uint)(param_9 != 0) * 8 + 1;
  iStack_30 = param_8;
  iStack_24 = iVar5;
  iVar3 = (*(code *)0x19a64)();
  if (iVar3 == 0) goto LAB_00410feb;
  uVar1 = iVar3 * 2;
  if ((uVar1 + 8 & -(uint)(uVar1 < uVar1 + 8)) == 0) {
    piVar4 = (undefined4 *)0x0;
LAB_00410ec0:
    if (((piVar4 == (undefined4 *)0x0) ||
        (iVar5 = (*(code *)0x19a64)(param_8,1,param_4,iVar5,piVar4,iVar3), iVar5 == 0)) ||
       (iVar5 = ___acrt_LCMapStringEx_36(param_2,param_3,piVar4,iVar3,0,0,0,0,0), iVar5 == 0))
    goto LAB_00410fe0;
    if ((param_3 & 0x400) == 0) {
      uVar1 = iVar5 * 2;
      if ((uVar1 + 8 & -(uint)(uVar1 < uVar1 + 8)) == 0) {
        piVar6 = (undefined4 *)0x0;
LAB_00410f9d:
        if ((piVar6 != (undefined4 *)0x0) &&
           (iVar3 = ___acrt_LCMapStringEx_36(param_2,param_3,piVar4,iVar3,piVar6,iVar5,0,0,0),
           iVar3 != 0)) {
          if (param_7 == 0) {
            param_7 = 0;
            param_6 = (char *)0x0;
          }
          iVar5 = (*(code *)0x19a7a)(param_8,0,piVar6,iVar5,param_6,param_7,0,0);
          if (iVar5 != 0) {
            __freea_crt((int)piVar6);
            goto LAB_00410fe2;
          }
        }
      }
      else if ((-(uint)(uVar1 < uVar1 + 8) & uVar1 + 8) < 0x401) {
        piVar6 = &iStack_30;
        if (&stack0x00000000 != (undefined1 *)0x30) {
          iStack_30 = 0xcccc;
          piVar6 = &iStack_30;
LAB_00410f96:
          piVar6 = piVar6 + 2;
          goto LAB_00410f9d;
        }
      }
      else {
        piVar6 = (int *)__malloc_base(-(uint)(uVar1 < uVar1 + 8) & uVar1 + 8);
        if (piVar6 != (undefined4 *)0x0) {
          *piVar6 = 0xdddd;
          goto LAB_00410f96;
        }
      }
      __freea_crt((int)piVar6);
      goto LAB_00410fe0;
    }
    if ((param_7 != 0) &&
       ((param_7 < iVar5 ||
        (iVar5 = ___acrt_LCMapStringEx_36(param_2,param_3,piVar4,iVar3,param_6,param_7,0,0,0),
        iVar5 == 0)))) goto LAB_00410fe0;
  }
  else {
    if ((-(uint)(uVar1 < uVar1 + 8) & uVar1 + 8) < 0x401) {
      piVar4 = &iStack_30;
      if (&stack0x00000000 != (undefined1 *)0x30) {
        iStack_30 = 0xcccc;
        piVar4 = &iStack_30;
LAB_00410eb9:
        piVar4 = piVar4 + 2;
        goto LAB_00410ec0;
      }
    }
    else {
      piVar4 = (int *)__malloc_base(-(uint)(uVar1 < uVar1 + 8) & uVar1 + 8);
      if (piVar4 != (undefined4 *)0x0) {
        *piVar4 = 0xdddd;
        goto LAB_00410eb9;
      }
    }
LAB_00410fe0:
    iVar5 = 0;
  }
LAB_00410fe2:
  iVar3 = iVar5;
  __freea_crt((int)piVar4);
LAB_00410feb:
  __security_check_cookie(uVar2 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___acrt_LCMapStringA
// 
// Library: Visual Studio 2015 Release

void __cdecl
___acrt_LCMapStringA
          (__crt_locale_pointers *param_1,wchar_t *param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  int local_14;
  __crt_locale_pointers local_10 [8];
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,param_1);
  __acrt_LCMapStringA_stat(local_10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9)
  ;
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  int __cdecl GetTableIndexFromLocaleName(wchar_t const *)
// 
// Library: Visual Studio 2015 Release

int __cdecl GetTableIndexFromLocaleName(wchar_t *param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  ushort uVar4;
  ushort *puVar5;
  int local_10;
  int local_c;
  int local_8;
  
  local_10 = 0;
  local_c = 0xe3;
  while( true ) {
    local_8 = 0x55;
    iVar2 = (local_c + local_10) / 2;
    puVar5 = (ushort *)(&PTR_DAT_00417010)[iVar2 * 2];
    iVar3 = (int)param_1 - (int)puVar5;
    do {
      uVar4 = *(ushort *)(iVar3 + (int)puVar5);
      if ((0x40 < uVar4) && (uVar4 < 0x5b)) {
        uVar4 = uVar4 + 0x20;
      }
      uVar1 = *puVar5;
      if ((0x40 < uVar1) && (uVar1 < 0x5b)) {
        uVar1 = uVar1 + 0x20;
      }
      puVar5 = puVar5 + 1;
      local_8 = local_8 + -1;
    } while (((local_8 != 0) && (uVar4 != 0)) && (uVar4 == uVar1));
    if ((uint)uVar4 == (uint)uVar1) break;
    if ((int)((uint)uVar4 - (uint)uVar1) < 0) {
      local_c = iVar2 + -1;
    }
    else {
      local_10 = iVar2 + 1;
    }
    if (local_c < local_10) {
      return -1;
    }
  }
  return *(int *)(&UNK_00417014 + iVar2 * 8);
}



// Library Function - Single Match
//  ___acrt_DownlevelLocaleNameToLCID
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl ___acrt_DownlevelLocaleNameToLCID(wchar_t *param_1)

{
  uint uVar1;
  
  if (param_1 != (wchar_t *)0x0) {
    uVar1 = GetTableIndexFromLocaleName(param_1);
    if ((-1 < (int)uVar1) && (uVar1 < 0xe4)) {
      return *(undefined4 *)(&DAT_00415ef0 + uVar1 * 8);
    }
  }
  return 0;
}



// Library Function - Multiple Matches With Different Base Names
//  __msize
//  __msize_base
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

size_t __cdecl FID_conflict___msize_base(void *_Memory)

{
  int *piVar1;
  size_t sVar2;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c975();
    return 0xffffffff;
  }
  sVar2 = (*(code *)0x19c34)(DAT_0041b5d0,0,_Memory);
  return sVar2;
}



// Library Function - Single Match
//  __realloc_base
// 
// Library: Visual Studio 2015 Release

int __cdecl __realloc_base(void *param_1,uint param_2)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 == (void *)0x0) {
    iVar1 = __malloc_base(param_2);
  }
  else {
    if (param_2 == 0) {
      FID_conflict__free(param_1);
    }
    else {
      if (param_2 < 0xffffffe1) {
        do {
          iVar1 = (*(code *)0x19c40)(DAT_0041b5d0,0,param_1,param_2);
          if (iVar1 != 0) {
            return iVar1;
          }
          iVar1 = FUN_0040bef8();
        } while ((iVar1 != 0) && (iVar1 = __callnewh(param_2), iVar1 != 0));
      }
      piVar2 = __errno();
      *piVar2 = 0xc;
    }
    iVar1 = 0;
  }
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___set_fpsr_sse2
// 
// Library: Visual Studio 2015 Release

void __cdecl ___set_fpsr_sse2(uint param_1)

{
  if (0 < DAT_0041ac24) {
    if (((param_1 & 0x40) == 0) || (DAT_0041a980 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}



// Library Function - Single Match
//  __clrfp
// 
// Library: Visual Studio 2015 Release

int __clrfp(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



// Library Function - Single Match
//  __ctrlfp
// 
// Library: Visual Studio 2015 Release

int __ctrlfp(void)

{
  short in_FPUControlWord;
  
  return (int)in_FPUControlWord;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00411294(void)

{
  return;
}



// Library Function - Single Match
//  __statfp
// 
// Library: Visual Studio 2015 Release

int __statfp(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Library: Visual Studio 2015 Release

int __cdecl __isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  int local_14;
  int *local_10;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,(__crt_locale_pointers *)_Locale);
  uVar1 = *(ushort *)(*local_10 + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



// Library Function - Single Match
//  ___dcrt_lowio_initialize_console_output
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void ___dcrt_lowio_initialize_console_output(void)

{
  DAT_0041a984 = (*(code *)0x19c4e)(L"CONOUT$",0x40000000,3,0,3,0,0);
  return;
}



// Library Function - Single Match
//  ___strncnt
// 
// Library: Visual Studio 2015 Release

void __cdecl ___strncnt(char *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  cVar1 = *param_1;
  while ((cVar1 != '\0' && (iVar2 != param_2))) {
    iVar2 = iVar2 + 1;
    cVar1 = param_1[iVar2];
  }
  return;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Library: Visual Studio

int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (_MaxCount != 0) {
    do {
      bVar2 = *_Str1;
      cVar1 = *_Str2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = _Str2 + 1;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar4 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
      }
      uVar3 = (ushort)uVar4;
      bVar2 = (byte)uVar4;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar3 = (ushort)CONCAT31((int3)(uVar4 >> 8),bVar2 + 0x20);
      }
      bVar2 = (byte)(uVar3 >> 8);
      bVar5 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) goto LAB_00411651;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00411651:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



void FUN_00411670(void)

{
  float10 in_ST0;
  
  FUN_0041168e((double)in_ST0);
  return;
}



float10 __cdecl FUN_0041168e(double param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  double dVar7;
  undefined1 in_XMM0 [16];
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double local_c;
  
  iVar4 = 0;
  while( true ) {
    uVar6 = in_XMM0._0_8_;
    uVar2 = (uint)(ushort)(in_XMM0._6_2_ >> 4);
    dVar7 = (double)(uVar6 & 0xfffffffffffff | 0x3ff0000000000000);
    uVar1 = SUB82(dVar7 + 4398046511103.008,0) & 0x7f0;
    dVar9 = (double)(uVar6 & 0xfffff80000000 | 0x3ff0000000000000);
    dVar11 = (double)(uVar6 & 0xfffff80000000 | 0x3ff0000000000000);
    dVar10 = dVar9 * *(double *)(&DAT_00418620 + uVar1) - 0.43359375;
    dVar7 = (dVar7 - dVar9) * *(double *)(&DAT_00418620 + uVar1);
    dVar8 = ((double)(uVar6 & 0xfffffffffffff | 0x3ff0000000000000) - dVar11) *
            *(double *)(&UNK_00418628 + uVar1);
    dVar9 = dVar7 + dVar10;
    in_XMM0._8_8_ = dVar8 + (dVar11 * *(double *)(&UNK_00418628 + uVar1) - 0.43359375);
    uVar3 = uVar2 - 1;
    if (uVar3 < 0x7fe) {
      iVar4 = (uVar2 - 0x3ff) + iVar4;
      dVar11 = (double)iVar4;
      iVar5 = 0;
      if (uVar1 + iVar4 * 0x400 == 0) {
        iVar5 = 0x10;
      }
      return (float10)(((in_XMM0._8_8_ * -3.0717952561537047 + 1.775881635348345) * in_XMM0._8_8_ +
                       -1.155016766740187) * in_XMM0._8_8_ * in_XMM0._8_8_ +
                       ((dVar9 * 21.535473262846583 + -10.893557852776363) * dVar9 +
                       5.667600603343536) * dVar9 * dVar9 * dVar9 * dVar9 * dVar9 +
                       dVar9 * 0.0016161024074997105 +
                       *(double *)(&UNK_00418218 + uVar1) + dVar11 * 2.8363394551044964e-14 +
                       (double)((ulonglong)dVar8 & *(ulonglong *)(&UNK_00418048 + iVar5)) +
                      *(double *)(&DAT_00418210 + uVar1) + dVar10 + dVar11 * 0.30102999566395283 +
                      (double)((ulonglong)dVar7 & *(ulonglong *)(&DAT_00418040 + iVar5)));
    }
    local_c = (double)-(ulonglong)(param_1 == 0.0);
    if (SUB82(local_c,0) != 0) break;
    if (uVar3 != 0xffffffff) {
      if (uVar3 < 0x7ff) {
        local_c = 2.225073858507201e-308;
        if ((double)((ulonglong)param_1 & 0xfffffffffffff | 0x3ff0000000000000) == 1.0) {
          return (float10)INFINITY;
        }
        iVar4 = 0x3e9;
      }
      else if (((uVar2 & 0x7ff) < 0x7ff) ||
              (SUB84(param_1,0) == 0 && ((ulonglong)param_1 & 0xfffff00000000) == 0)) {
        local_c = NAN;
        iVar4 = 9;
      }
      else {
        iVar4 = 0x3e9;
      }
      goto LAB_0041189a;
    }
    in_XMM0._0_8_ = param_1 * 4503599627370496.0;
    iVar4 = -0x34;
  }
  local_c = -INFINITY;
  iVar4 = 8;
LAB_0041189a:
  ___libm_error_support(&param_1,&param_1,&local_c,iVar4);
  return (float10)local_c;
}



float10 __fastcall
FUN_00411e90(undefined4 param_1,int param_2,undefined2 param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float10 in_ST0;
  int local_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 local_14;
  undefined4 local_10;
  double dStack_c;
  
  local_14 = param_7;
  local_10 = param_8;
  dStack_c = (double)in_ST0;
  uStack_1c = param_5;
  uStack_18 = param_6;
  uStack_20 = param_1;
  __87except(param_2,&local_24,&param_3);
  return (float10)dStack_c;
}



// Library Function - Single Match
//  __startOneArgErrorHandling
// 
// Library: Visual Studio 2015 Release

float10 __fastcall
__startOneArgErrorHandling
          (undefined4 param_1,int param_2,ushort param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6)

{
  float10 in_ST0;
  int local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  double local_c;
  
  local_c = (double)in_ST0;
  local_1c = param_5;
  local_18 = param_6;
  local_20 = param_1;
  __87except(param_2,&local_24,&param_3);
  return (float10)local_c;
}



// Library Function - Single Match
//  ___libm_error_support
// 
// Library: Visual Studio 2015 Release

void __cdecl
___libm_error_support(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,int param_4)

{
  undefined8 uVar1;
  code *pcVar2;
  int iVar3;
  int *piVar4;
  undefined4 *puVar5;
  undefined4 local_28;
  char *local_24;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  uint local_8;
  
  local_8 = DAT_0041a208 ^ (uint)&stack0xfffffffc;
  if (DAT_0041b5f0 == 0) {
    pcVar2 = ___acrt_invoke_user_matherr;
  }
  else {
    pcVar2 = (code *)(*(code *)0x19c5c)(DAT_0041b604);
  }
  if (0x1a < param_4) {
    if (param_4 != 0x1b) {
      if (param_4 == 0x1c) {
        local_24 = "pow";
      }
      else if (param_4 == 0x31) {
        local_24 = "sqrt";
      }
      else if (param_4 == 0x3a) {
        local_24 = "acos";
      }
      else {
        if (param_4 != 0x3d) {
          if ((param_4 != 1000) && (param_4 != 0x3e9)) goto LAB_004120eb;
          uVar1 = *param_1;
          goto LAB_00412038;
        }
        local_24 = "asin";
      }
      goto LAB_00411f57;
    }
    local_28 = 2;
LAB_004120a9:
    local_24 = "pow";
    goto LAB_004120b0;
  }
  if (param_4 == 0x1a) {
    uVar1 = 0x3ff0000000000000;
LAB_00412038:
    *param_3 = uVar1;
    goto LAB_004120eb;
  }
  if (param_4 < 0xf) {
    if (param_4 == 0xe) {
      local_28 = 3;
      local_24 = "exp";
    }
    else {
      if (param_4 != 2) {
        if (param_4 == 3) {
          local_24 = "log";
        }
        else {
          if (param_4 == 8) {
            local_28 = 2;
            local_24 = "log10";
            goto LAB_004120b0;
          }
          if (param_4 != 9) goto LAB_004120eb;
          local_24 = "log10";
        }
LAB_00411f57:
        local_28 = 1;
        local_20 = *param_1;
        local_18 = *param_2;
        puVar5 = &local_28;
        local_10 = *param_3;
        guard_check_icall();
        iVar3 = (*pcVar2)(puVar5);
        if (iVar3 == 0) {
          piVar4 = __errno();
          *piVar4 = 0x21;
        }
        goto LAB_004120e6;
      }
      local_28 = 2;
      local_24 = "log";
    }
LAB_004120b0:
    local_20 = *param_1;
    local_18 = *param_2;
    puVar5 = &local_28;
    local_10 = *param_3;
    guard_check_icall();
    iVar3 = (*pcVar2)(puVar5);
    if (iVar3 == 0) {
      piVar4 = __errno();
      *piVar4 = 0x22;
    }
  }
  else {
    if (param_4 == 0xf) {
      local_24 = "exp";
    }
    else {
      if (param_4 == 0x18) {
        local_28 = 3;
        goto LAB_004120a9;
      }
      if (param_4 != 0x19) goto LAB_004120eb;
      local_24 = "pow";
    }
    local_28 = 4;
    local_20 = *param_1;
    local_18 = *param_2;
    puVar5 = &local_28;
    local_10 = *param_3;
    guard_check_icall();
    (*pcVar2)(puVar5);
  }
LAB_004120e6:
  *param_3 = local_10;
LAB_004120eb:
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



float10 __cdecl FUN_004120fb(double param_1)

{
  double dVar1;
  uint uVar2;
  int iVar3;
  float10 fVar4;
  uint uVar5;
  
  uVar2 = __ctrlfp();
  if ((param_1._6_2_ & 0x7ff0) == 0x7ff0) {
    iVar3 = __sptype(SUB84(param_1,0),(uint)((ulonglong)param_1 >> 0x20));
    if (iVar3 - 1U < 3) {
      __ctrlfp();
      return (float10)param_1;
    }
    dVar1 = param_1 + 1.0;
    uVar5 = 8;
  }
  else {
    fVar4 = FUN_00412454(param_1);
    if (((NAN((float10)param_1) || NAN(fVar4)) != ((float10)param_1 == fVar4)) ||
       ((uVar2 & 0x20) != 0)) {
      __ctrlfp();
      return (float10)(double)fVar4;
    }
    dVar1 = (double)fVar4;
    uVar5 = 0x10;
  }
  fVar4 = (float10)__except1(uVar5,0xc,param_1,dVar1,uVar2);
  return fVar4;
}



undefined4 __cdecl FUN_004121b4(double param_1)

{
  uint uVar1;
  float10 fVar2;
  float10 fVar3;
  
  uVar1 = __fpclass(param_1);
  if ((uVar1 & 0x90) == 0) {
    fVar2 = FUN_00412454(param_1);
    fVar3 = (float10)param_1;
    if ((NAN(fVar3) || NAN(fVar2)) != (fVar3 == fVar2)) {
      fVar2 = FUN_00412454((double)(fVar3 * (float10)0.5));
      fVar3 = (float10)(double)(fVar3 * (float10)0.5);
      if ((NAN(fVar3) || NAN(fVar2)) != (fVar3 == fVar2)) {
        return 2;
      }
      return 1;
    }
  }
  return 0;
}



undefined4 __cdecl FUN_0041221e(int param_1,int param_2,int param_3,int param_4,undefined8 *param_5)

{
  double dVar1;
  undefined8 uVar2;
  int iVar3;
  
  dVar1 = ABS((double)CONCAT44(param_2,param_1));
  if (param_4 == 0x7ff00000) {
    if (param_3 != 0) goto LAB_004122b2;
    uVar2 = 0x3ff0000000000000;
    if (1.0 < dVar1 == NAN(dVar1)) {
      if (dVar1 < 1.0) {
        uVar2 = 0;
      }
      goto LAB_00412343;
    }
  }
  else {
    if ((param_4 == -0x100000) && (param_3 == 0)) {
      if (1.0 < dVar1 == NAN(dVar1)) {
        uVar2 = 0x3ff0000000000000;
        if (dVar1 < 1.0) {
          uVar2 = 0x7ff0000000000000;
        }
      }
      else {
        uVar2 = 0;
      }
      goto LAB_00412343;
    }
LAB_004122b2:
    if (param_2 != 0x7ff00000) {
      if (param_2 != -0x100000) {
        return 0;
      }
      if (param_1 != 0) {
        return 0;
      }
      iVar3 = FUN_004121b4((double)CONCAT44(param_4,param_3));
      uVar2 = 0;
      dVar1 = (double)CONCAT44(param_4,param_3);
      if (dVar1 <= 0.0) {
        if (dVar1 < 0.0 == NAN(dVar1)) {
          uVar2 = 0x3ff0000000000000;
        }
        else if (iVar3 == 1) {
          uVar2 = 0x8000000000000000;
        }
      }
      else {
        uVar2 = 0x7ff0000000000000;
        if (iVar3 == 1) {
          uVar2 = 0xfff0000000000000;
        }
      }
      goto LAB_00412343;
    }
    if (param_1 != 0) {
      return 0;
    }
    dVar1 = (double)CONCAT44(param_4,param_3);
    if (dVar1 <= 0.0) {
      uVar2 = 0;
      if (dVar1 < 0.0 == NAN(dVar1)) {
        uVar2 = 0x3ff0000000000000;
      }
      goto LAB_00412343;
    }
  }
  uVar2 = 0x7ff0000000000000;
LAB_00412343:
  *param_5 = uVar2;
  return 0;
}



// Library Function - Single Match
//  __87except
// 
// Library: Visual Studio 2015 Release

void __cdecl __87except(int param_1,int *param_2,ushort *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  uint uVar3;
  uint local_94;
  uint local_90 [12];
  undefined8 local_60;
  uint local_50;
  uint local_14;
  
  local_14 = DAT_0041a208 ^ (uint)&stack0xfffffff0;
  local_94 = (uint)*param_3;
  iVar2 = *param_2;
  if (iVar2 == 1) {
LAB_004123b1:
    uVar3 = 8;
  }
  else if (iVar2 == 2) {
    uVar3 = 4;
  }
  else if (iVar2 == 3) {
    uVar3 = 0x11;
  }
  else if (iVar2 == 4) {
    uVar3 = 0x12;
  }
  else {
    if (iVar2 == 5) goto LAB_004123b1;
    if (iVar2 != 8) goto LAB_00412413;
    uVar3 = 0x10;
  }
  bVar1 = __handle_exc(uVar3,(double *)(param_2 + 6),local_94);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    if (((param_1 == 0x10) || (param_1 == 0x16)) || (param_1 == 0x1d)) {
      local_60 = *(undefined8 *)(param_2 + 4);
      local_50 = local_50 & 0xffffffe3 | 3;
    }
    else {
      local_50 = local_50 & 0xfffffffe;
    }
    __raise_exc(local_90,&local_94,uVar3,param_1,(uint *)(param_2 + 2),(uint *)(param_2 + 6));
  }
LAB_00412413:
  __ctrlfp();
  if (((*param_2 == 8) || (bVar1 = ___acrt_has_user_matherr(), !bVar1)) ||
     (iVar2 = ___acrt_invoke_user_matherr(param_2), iVar2 == 0)) {
    __set_errno_from_matherr(*param_2);
  }
  __security_check_cookie(local_14 ^ (uint)&stack0xfffffff0);
  return;
}



float10 __cdecl FUN_00412454(double param_1)

{
  return (float10)ROUND(param_1);
}



// Library Function - Single Match
//  __errcode
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __errcode(uint param_1)

{
  undefined4 uStack_8;
  
  if ((param_1 & 0x20) == 0) {
    if ((param_1 & 8) != 0) {
      return 1;
    }
    if ((param_1 & 4) == 0) {
      if ((param_1 & 1) == 0) {
        return (param_1 & 2) * 2;
      }
      uStack_8 = 3;
    }
    else {
      uStack_8 = 2;
    }
  }
  else {
    uStack_8 = 5;
  }
  return uStack_8;
}



// Library Function - Single Match
//  __except1
// 
// Library: Visual Studio 2015 Release

void __cdecl __except1(uint param_1,int param_2,undefined8 param_3,double param_4,uint param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  uint local_90 [16];
  uint local_50;
  uint local_14;
  
  local_14 = DAT_0041a208 ^ (uint)&stack0xfffffff0;
  bVar1 = __handle_exc(param_1,&param_4,param_5);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_50 = local_50 & 0xfffffffe;
    __raise_exc_ex(local_90,&param_5,param_1,param_2,(uint *)&param_3,(uint *)&param_4,0);
  }
  iVar2 = __errcode(param_1);
  bVar1 = ___acrt_has_user_matherr();
  if ((bVar1) && (iVar2 != 0)) {
    __umatherr(iVar2,param_2,(int)param_3,(int)((ulonglong)param_3 >> 0x20),0,0,SUB84(param_4,0),
               (int)((ulonglong)param_4 >> 0x20));
  }
  else {
    __set_errno_from_matherr(iVar2);
    __ctrlfp();
  }
  __security_check_cookie(local_14 ^ (uint)&stack0xfffffff0);
  return;
}



// Library Function - Single Match
//  __handle_exc
// 
// Library: Visual Studio 2015 Release

bool __cdecl __handle_exc(uint param_1,double *param_2,uint param_3)

{
  double dVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  float10 fVar5;
  float10 fVar6;
  uint local_14;
  byte bStack_10;
  undefined1 uStack_f;
  ushort uStack_e;
  int local_8;
  
  uVar3 = param_1 & 0x1f;
  if (((param_1 & 8) != 0) && ((param_3 & 1) != 0)) {
    FUN_00411294();
    uVar3 = param_1 & 0x17;
    goto LAB_00412729;
  }
  if ((param_1 & param_3 & 4) != 0) {
    FUN_00411294();
    uVar3 = param_1 & 0x1b;
    goto LAB_00412729;
  }
  if (((param_1 & 1) == 0) || ((param_3 & 8) == 0)) {
    if (((param_1 & 2) != 0) && ((param_3 & 0x10) != 0)) {
      bVar4 = (param_1 & 0x10) != 0;
      if (NAN(*param_2) == (*param_2 == 0.0)) {
        fVar5 = (float10)FUN_00412b31(SUB84(*param_2,0),(uint)((ulonglong)*param_2 >> 0x20),&local_8
                                     );
        local_8 = local_8 + -0x600;
        dVar1 = (double)fVar5;
        local_14 = SUB84(dVar1,0);
        bStack_10 = (byte)((ulonglong)dVar1 >> 0x20);
        uStack_f = (undefined1)((ulonglong)dVar1 >> 0x28);
        uStack_e = (ushort)((ulonglong)dVar1 >> 0x30);
        if (local_8 < -0x432) {
          fVar6 = (float10)0 * fVar5;
          bVar4 = true;
        }
        else {
          uStack_e = uStack_e & 0xf | 0x10;
          if (local_8 < -0x3fd) {
            iVar2 = -0x3fd - local_8;
            do {
              if (((local_14 & 1) != 0) && (!bVar4)) {
                bVar4 = true;
              }
              local_14 = local_14 >> 1;
              if ((bStack_10 & 1) != 0) {
                local_14 = local_14 | 0x80000000;
              }
              uVar3 = CONCAT22(uStack_e,CONCAT11(uStack_f,bStack_10)) >> 1;
              bStack_10 = (byte)uVar3;
              uStack_f = (undefined1)(uVar3 >> 8);
              uStack_e = uStack_e >> 1;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
          fVar6 = (float10)(double)CONCAT26(uStack_e,CONCAT15(uStack_f,CONCAT14(bStack_10,local_14))
                                           );
          if (fVar5 < (float10)0) {
            fVar6 = -fVar6;
          }
        }
        *param_2 = (double)fVar6;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_00411294();
      }
      uVar3 = param_1 & 0x1d;
    }
    goto LAB_00412729;
  }
  FUN_00411294();
  uVar3 = param_3 & 0xc00;
  if (uVar3 == 0) {
    if (0.0 < *param_2 == NAN(*param_2)) {
LAB_00412643:
      dVar1 = INFINITY;
      goto LAB_00412649;
    }
LAB_0041263b:
    dVar1 = INFINITY;
LAB_0041264b:
    *param_2 = dVar1;
  }
  else {
    if (uVar3 == 0x400) {
      if (0.0 < *param_2 == NAN(*param_2)) goto LAB_00412643;
      dVar1 = 1.7976931348623157e+308;
      goto LAB_0041264b;
    }
    if (uVar3 == 0x800) {
      if (0.0 < *param_2 != NAN(*param_2)) goto LAB_0041263b;
      dVar1 = 1.7976931348623157e+308;
LAB_00412649:
      dVar1 = -dVar1;
      goto LAB_0041264b;
    }
    if (uVar3 == 0xc00) {
      dVar1 = 1.7976931348623157e+308;
      if (0.0 < *param_2 != NAN(*param_2)) goto LAB_0041264b;
      goto LAB_00412649;
    }
  }
  uVar3 = param_1 & 0x1e;
LAB_00412729:
  if (((param_1 & 0x10) != 0) && ((param_3 & 0x20) != 0)) {
    FUN_00411294();
    uVar3 = uVar3 & 0xffffffef;
  }
  return uVar3 == 0;
}



// Library Function - Single Match
//  __raise_exc
// 
// Library: Visual Studio 2015 Release

void __cdecl
__raise_exc(uint *param_1,uint *param_2,uint param_3,int param_4,uint *param_5,uint *param_6)

{
  __raise_exc_ex(param_1,param_2,param_3,param_4,param_5,param_6,0);
  return;
}



// Library Function - Single Match
//  __raise_exc_ex
// 
// Library: Visual Studio 2015 Release

void __cdecl
__raise_exc_ex(uint *param_1,uint *param_2,uint param_3,int param_4,uint *param_5,uint *param_6,
              int param_7)

{
  uint *puVar1;
  uint *puVar2;
  uint uVar3;
  undefined4 uVar4;
  
  puVar1 = param_2;
  param_1[1] = 0;
  uVar4 = 0xc000000d;
  param_1[2] = 0;
  param_1[3] = 0;
  if ((param_3 & 0x10) != 0) {
    uVar4 = 0xc000008f;
    param_1[1] = param_1[1] | 1;
  }
  if ((param_3 & 2) != 0) {
    uVar4 = 0xc0000093;
    param_1[1] = param_1[1] | 2;
  }
  if ((param_3 & 1) != 0) {
    uVar4 = 0xc0000091;
    param_1[1] = param_1[1] | 4;
  }
  if ((param_3 & 4) != 0) {
    uVar4 = 0xc000008e;
    param_1[1] = param_1[1] | 8;
  }
  if ((param_3 & 8) != 0) {
    uVar4 = 0xc0000090;
    param_1[1] = param_1[1] | 0x10;
  }
  param_1[2] = param_1[2] ^ (~(*param_2 << 4) ^ param_1[2]) & 0x10;
  param_1[2] = param_1[2] ^ (~(*param_2 * 2) ^ param_1[2]) & 8;
  param_1[2] = param_1[2] ^ (~(*param_2 >> 1) ^ param_1[2]) & 4;
  param_1[2] = param_1[2] ^ (~(*param_2 >> 3) ^ param_1[2]) & 2;
  param_1[2] = param_1[2] ^ (~(*param_2 >> 5) ^ param_1[2]) & 1;
  uVar3 = __statfp();
  puVar2 = param_6;
  if ((uVar3 & 1) != 0) {
    param_1[3] = param_1[3] | 0x10;
  }
  if ((uVar3 & 4) != 0) {
    param_1[3] = param_1[3] | 8;
  }
  if ((uVar3 & 8) != 0) {
    param_1[3] = param_1[3] | 4;
  }
  if ((uVar3 & 0x10) != 0) {
    param_1[3] = param_1[3] | 2;
  }
  if ((uVar3 & 0x20) != 0) {
    param_1[3] = param_1[3] | 1;
  }
  uVar3 = *puVar1 & 0xc00;
  if (uVar3 == 0) {
    *param_1 = *param_1 & 0xfffffffc;
  }
  else {
    if (uVar3 == 0x400) {
      uVar3 = *param_1 & 0xfffffffd | 1;
    }
    else {
      if (uVar3 != 0x800) {
        if (uVar3 == 0xc00) {
          *param_1 = *param_1 | 3;
        }
        goto LAB_004128d1;
      }
      uVar3 = *param_1 & 0xfffffffe | 2;
    }
    *param_1 = uVar3;
  }
LAB_004128d1:
  uVar3 = *puVar1 & 0x300;
  if (uVar3 == 0) {
    uVar3 = *param_1 & 0xffffffeb | 8;
LAB_00412907:
    *param_1 = uVar3;
  }
  else {
    if (uVar3 == 0x200) {
      uVar3 = *param_1 & 0xffffffe7 | 4;
      goto LAB_00412907;
    }
    if (uVar3 == 0x300) {
      *param_1 = *param_1 & 0xffffffe3;
    }
  }
  *param_1 = *param_1 ^ (param_4 << 5 ^ *param_1) & 0x1ffe0;
  param_1[8] = param_1[8] | 1;
  if (param_7 == 0) {
    param_1[8] = param_1[8] & 0xffffffe3 | 2;
    *(undefined8 *)(param_1 + 4) = *(undefined8 *)param_5;
    param_1[0x18] = param_1[0x18] | 1;
    param_1[0x18] = param_1[0x18] & 0xffffffe3 | 2;
    *(undefined8 *)(param_1 + 0x14) = *(undefined8 *)param_6;
  }
  else {
    param_1[8] = param_1[8] & 0xffffffe1;
    param_1[4] = *param_5;
    param_1[0x18] = param_1[0x18] | 1;
    param_1[0x18] = param_1[0x18] & 0xffffffe1;
    param_1[0x14] = *param_6;
  }
  __clrfp();
  (*(code *)0x19940)(uVar4,0,1,&param_1);
  if ((param_1[2] & 0x10) != 0) {
    *puVar1 = *puVar1 & 0xfffffffe;
  }
  if ((param_1[2] & 8) != 0) {
    *puVar1 = *puVar1 & 0xfffffffb;
  }
  if ((param_1[2] & 4) != 0) {
    *puVar1 = *puVar1 & 0xfffffff7;
  }
  if ((param_1[2] & 2) != 0) {
    *puVar1 = *puVar1 & 0xffffffef;
  }
  if ((param_1[2] & 1) != 0) {
    *puVar1 = *puVar1 & 0xffffffdf;
  }
  uVar3 = *param_1 & 3;
  if (uVar3 == 0) {
    *puVar1 = *puVar1 & 0xfffff3ff;
  }
  else {
    if (uVar3 == 1) {
      uVar3 = *puVar1 & 0xfffff7ff | 0x400;
    }
    else {
      if (uVar3 != 2) {
        if (uVar3 == 3) {
          *puVar1 = *puVar1 | 0xc00;
        }
        goto LAB_00412a18;
      }
      uVar3 = *puVar1 & 0xfffffbff | 0x800;
    }
    *puVar1 = uVar3;
  }
LAB_00412a18:
  uVar3 = *param_1 >> 2 & 7;
  if (uVar3 == 0) {
    uVar3 = *puVar1 & 0xfffff3ff | 0x300;
  }
  else {
    if (uVar3 != 1) {
      if (uVar3 == 2) {
        *puVar1 = *puVar1 & 0xfffff3ff;
      }
      goto LAB_00412a49;
    }
    uVar3 = *puVar1 & 0xfffff3ff | 0x200;
  }
  *puVar1 = uVar3;
LAB_00412a49:
  if (param_7 == 0) {
    *(undefined8 *)puVar2 = *(undefined8 *)(param_1 + 0x14);
  }
  else {
    *puVar2 = param_1[0x14];
  }
  return;
}



// Library Function - Single Match
//  __set_errno_from_matherr
// 
// Library: Visual Studio 2015 Release

void __cdecl __set_errno_from_matherr(int param_1)

{
  int *piVar1;
  
  if (param_1 == 1) {
    piVar1 = __errno();
    *piVar1 = 0x21;
  }
  else if (param_1 - 2U < 2) {
    piVar1 = __errno();
    *piVar1 = 0x22;
    return;
  }
  return;
}



// Library Function - Single Match
//  __umatherr
// 
// Library: Visual Studio 2015 Release

float10 __cdecl
__umatherr(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  double dVar1;
  int iVar2;
  int local_24;
  undefined *local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 uStack_8;
  
  local_20 = (undefined *)0x0;
  iVar2 = 0;
  do {
    if ((&DAT_00418ac8)[iVar2 * 2] == param_2) {
      local_20 = (&PTR_DAT_00418acc)[iVar2 * 2];
      break;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x1d);
  if (local_20 == (undefined *)0x0) {
    __ctrlfp();
    __set_errno_from_matherr(param_1);
    dVar1 = (double)CONCAT44(param_8,param_7);
  }
  else {
    local_1c = param_3;
    local_18 = param_4;
    local_14 = param_5;
    local_10 = param_6;
    local_c = param_7;
    local_24 = param_1;
    uStack_8 = param_8;
    __ctrlfp();
    iVar2 = ___acrt_invoke_user_matherr(&local_24);
    if (iVar2 == 0) {
      __set_errno_from_matherr(param_1);
    }
    dVar1 = (double)CONCAT44(uStack_8,local_c);
  }
  return (float10)dVar1;
}



void __cdecl FUN_00412b31(int param_1,uint param_2,int *param_3)

{
  uint uVar1;
  double dVar2;
  uint uVar3;
  ushort uVar4;
  int iVar5;
  
  dVar2 = (double)CONCAT17(param_2._3_1_,
                           CONCAT16(param_2._2_1_,CONCAT24((undefined2)param_2,param_1)));
  if (NAN(dVar2) == (dVar2 == 0.0)) {
    if (((param_2 & 0x7ff00000) == 0) && (((param_2 & 0xfffff) != 0 || (param_1 != 0)))) {
      iVar5 = -0x3fd;
      uVar3 = param_2;
      if ((param_2 & 0x100000) == 0) {
        do {
          uVar1 = uVar3 * 2;
          param_2._0_2_ = (undefined2)uVar1;
          uVar3 = uVar1;
          if (param_1 < 0) {
            uVar3 = uVar1 | 1;
            param_2._0_2_ = (undefined2)uVar3;
          }
          param_1 = param_1 * 2;
          iVar5 = iVar5 + -1;
        } while ((uVar1 & 0x100000) == 0);
        param_2 = CONCAT22((short)(uVar1 >> 0x10),(undefined2)param_2);
      }
      uVar4 = (ushort)(param_2 >> 0x10) & 0xffef;
      param_2._2_1_ = (undefined1)uVar4;
      param_2._3_1_ = (byte)(uVar4 >> 8);
      if (dVar2 < 0.0) {
        param_2._3_1_ = param_2._3_1_ | 0x80;
      }
      __set_exp(CONCAT17(param_2._3_1_,CONCAT16(param_2._2_1_,CONCAT24((undefined2)param_2,param_1))
                        ),0);
    }
    else {
      __set_exp(dVar2,0);
      iVar5 = (param_2 >> 0x14 & 0x7ff) - 0x3fe;
    }
  }
  else {
    iVar5 = 0;
  }
  *param_3 = iVar5;
  return;
}



// Library Function - Single Match
//  __set_exp
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

float10 __cdecl __set_exp(undefined8 param_1,short param_2)

{
  undefined8 local_c;
  
  local_c = (double)CONCAT26((param_2 + 0x3fe) * 0x10 | param_1._6_2_ & 0x800f,(int6)param_1);
  return (float10)local_c;
}



// Library Function - Single Match
//  __sptype
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl __sptype(int param_1,uint param_2)

{
  undefined4 uStack_8;
  
  if (param_2 == 0x7ff00000) {
    if (param_1 == 0) {
      return 1;
    }
  }
  else if ((param_2 == 0xfff00000) && (param_1 == 0)) {
    return 2;
  }
  if ((param_2._2_2_ & 0x7ff8) == 0x7ff8) {
    uStack_8 = 3;
  }
  else {
    if (((param_2._2_2_ & 0x7ff8) != 0x7ff0) || (((param_2 & 0x7ffff) == 0 && (param_1 == 0)))) {
      return 0;
    }
    uStack_8 = 4;
  }
  return uStack_8;
}



// Library Function - Single Match
//  __fpclass
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __fpclass(double _X)

{
  int iVar1;
  
  if ((_X._6_2_ & 0x7ff0) == 0x7ff0) {
    iVar1 = __sptype(_X._0_4_,(uint)((ulonglong)_X >> 0x20));
    if (iVar1 == 1) {
      return 0x200;
    }
    if (iVar1 == 2) {
      iVar1 = 4;
    }
    else {
      if (iVar1 != 3) {
        return 1;
      }
      iVar1 = 2;
    }
    return iVar1;
  }
  if ((((ulonglong)_X & 0x7ff0000000000000) == 0) &&
     ((((ulonglong)_X & 0xfffff00000000) != 0 || (_X._0_4_ != 0)))) {
    return (-(uint)(((ulonglong)_X & 0x8000000000000000) != 0) & 0xffffff90) + 0x80;
  }
  if (NAN(_X) != (_X == 0.0)) {
    return (-(uint)(((ulonglong)_X & 0x8000000000000000) != 0) & 0xffffffe0) + 0x40;
  }
  return (-(uint)(((ulonglong)_X & 0x8000000000000000) != 0) & 0xffffff08) + 0x100;
}



void FUN_00412d36(void)

{
  (*(code *)0x198c2)();
  return;
}



void FUN_00412d3c(void)

{
  (*(code *)0x199de)();
  return;
}



// Library Function - Single Match
//  __FindPESection
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  uVar3 = 0;
  iVar1 = *(int *)(pImageBase + 0x3c);
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2019 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  void *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = FUN_0040a530;
  local_14 = ExceptionList;
  local_c = DAT_0041a208 ^ 0x4195a8;
  ExceptionList = &local_14;
  local_8 = 0;
  BVar1 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_00400000);
  if (BVar1 != 0) {
    p_Var2 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_00400000,(DWORD_PTR)(pTarget + -0x400000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0) {
      ExceptionList = local_14;
      return ~(p_Var2->Characteristics >> 0x1f) & 1;
    }
  }
  ExceptionList = local_14;
  return 0;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  
  if (*(short *)pImageBase != 0x5a4d) {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
    uVar1 = (uint)((short)*(int *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b)
    ;
  }
  return uVar1;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4_GS
// 
// Library: Visual Studio 2015 Release

void __cdecl __SEH_prolog4_GS(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined1 local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0041a208 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_00412f89(void)

{
  uint unaff_EBP;
  
  __security_check_cookie(*(uint *)(unaff_EBP - 0x1c) ^ unaff_EBP);
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __alloca_probe
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __alloca_probe(void)

{
  undefined1 *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined1 auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio 2015 Release

uint __alloca_probe_16(void)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 0xf;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

uint __alloca_probe_8(void)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 7;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



ulonglong __cdecl FUN_00413220(uint *param_1,uint *param_2,uint param_3)

{
  undefined8 uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined4 uVar26;
  undefined4 uVar27;
  undefined4 uVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  undefined4 uVar31;
  undefined4 uVar32;
  undefined4 uVar33;
  uint uVar34;
  uint uVar35;
  uint uVar36;
  uint uVar37;
  uint uVar38;
  uint uVar39;
  uint uVar40;
  uint uVar41;
  uint uVar42;
  uint uVar43;
  uint uVar44;
  uint uVar45;
  uint uVar46;
  uint uVar47;
  uint *puVar48;
  undefined4 *puVar49;
  undefined4 *puVar50;
  uint *puVar51;
  undefined4 *puVar52;
  undefined4 *puVar53;
  uint uVar54;
  ulonglong uVar55;
  
  if ((param_2 < param_1) && (param_1 < (uint *)(param_3 + (int)param_2))) {
    puVar49 = (undefined4 *)(param_3 + (int)param_2);
    puVar52 = (undefined4 *)(param_3 + (int)param_1);
    uVar46 = param_3;
    uVar47 = param_3;
    if (0x1f < param_3) {
      if ((DAT_0041a200 >> 1 & 1) == 0) {
        if (((uint)puVar52 & 3) != 0) {
          uVar47 = (uint)puVar52 & 3;
          param_3 = param_3 - uVar47;
          do {
            *(undefined1 *)((int)puVar52 - 1) = *(undefined1 *)((int)puVar49 + -1);
            puVar49 = (undefined4 *)((int)puVar49 + -1);
            puVar52 = (undefined4 *)((int)puVar52 - 1);
            uVar47 = uVar47 - 1;
          } while (uVar47 != 0);
        }
        uVar46 = param_3;
        if (0x1f < param_3) {
          uVar46 = param_3 >> 2;
          while( true ) {
            if (uVar46 == 0) break;
            uVar46 = uVar46 - 1;
            puVar52[-1] = puVar49[-1];
            puVar49 = puVar49 + -1;
            puVar52 = puVar52 + -1;
          }
          switch(param_3 & 3) {
          case 0:
            return CONCAT44(param_3,param_1) & 0x3ffffffff;
          case 1:
            *(undefined1 *)((int)puVar52 - 1) = *(undefined1 *)((int)puVar49 + -1);
            return CONCAT44(param_3,param_1) & 0x3ffffffff;
          case 2:
            *(undefined1 *)((int)puVar52 - 1) = *(undefined1 *)((int)puVar49 + -1);
            *(undefined1 *)((int)puVar52 - 2) = *(undefined1 *)((int)puVar49 + -2);
            return CONCAT44(param_3,param_1) & 0x3ffffffff;
          case 3:
            *(undefined1 *)((int)puVar52 - 1) = *(undefined1 *)((int)puVar49 + -1);
            *(undefined1 *)((int)puVar52 - 2) = *(undefined1 *)((int)puVar49 + -2);
            *(undefined1 *)((int)puVar52 - 3) = *(undefined1 *)((int)puVar49 + -3);
            return CONCAT44(param_3,param_1) & 0x3ffffffff;
          }
        }
      }
      else {
        while (puVar50 = puVar49, puVar53 = puVar52, ((uint)puVar52 & 0xf) != 0) {
          puVar49 = (undefined4 *)((int)puVar49 + -1);
          puVar52 = (undefined4 *)((int)puVar52 + -1);
          *(undefined1 *)puVar52 = *(undefined1 *)puVar49;
          uVar46 = uVar46 - 1;
        }
        do {
          puVar49 = puVar50;
          puVar52 = puVar53;
          if (uVar46 < 0x80) break;
          puVar49 = puVar50 + -0x20;
          puVar52 = puVar53 + -0x20;
          uVar3 = puVar50[-0x1f];
          uVar4 = puVar50[-0x1e];
          uVar5 = puVar50[-0x1d];
          uVar6 = puVar50[-0x1c];
          uVar7 = puVar50[-0x1b];
          uVar8 = puVar50[-0x1a];
          uVar9 = puVar50[-0x19];
          uVar10 = puVar50[-0x18];
          uVar11 = puVar50[-0x17];
          uVar12 = puVar50[-0x16];
          uVar13 = puVar50[-0x15];
          uVar14 = puVar50[-0x14];
          uVar15 = puVar50[-0x13];
          uVar16 = puVar50[-0x12];
          uVar17 = puVar50[-0x11];
          uVar18 = puVar50[-0x10];
          uVar19 = puVar50[-0xf];
          uVar20 = puVar50[-0xe];
          uVar21 = puVar50[-0xd];
          uVar22 = puVar50[-0xc];
          uVar23 = puVar50[-0xb];
          uVar24 = puVar50[-10];
          uVar25 = puVar50[-9];
          uVar26 = puVar50[-8];
          uVar27 = puVar50[-7];
          uVar28 = puVar50[-6];
          uVar29 = puVar50[-5];
          uVar30 = puVar50[-4];
          uVar31 = puVar50[-3];
          uVar32 = puVar50[-2];
          uVar33 = puVar50[-1];
          *puVar52 = *puVar49;
          puVar53[-0x1f] = uVar3;
          puVar53[-0x1e] = uVar4;
          puVar53[-0x1d] = uVar5;
          puVar53[-0x1c] = uVar6;
          puVar53[-0x1b] = uVar7;
          puVar53[-0x1a] = uVar8;
          puVar53[-0x19] = uVar9;
          puVar53[-0x18] = uVar10;
          puVar53[-0x17] = uVar11;
          puVar53[-0x16] = uVar12;
          puVar53[-0x15] = uVar13;
          puVar53[-0x14] = uVar14;
          puVar53[-0x13] = uVar15;
          puVar53[-0x12] = uVar16;
          puVar53[-0x11] = uVar17;
          puVar53[-0x10] = uVar18;
          puVar53[-0xf] = uVar19;
          puVar53[-0xe] = uVar20;
          puVar53[-0xd] = uVar21;
          puVar53[-0xc] = uVar22;
          puVar53[-0xb] = uVar23;
          puVar53[-10] = uVar24;
          puVar53[-9] = uVar25;
          puVar53[-8] = uVar26;
          puVar53[-7] = uVar27;
          puVar53[-6] = uVar28;
          puVar53[-5] = uVar29;
          puVar53[-4] = uVar30;
          puVar53[-3] = uVar31;
          puVar53[-2] = uVar32;
          puVar53[-1] = uVar33;
          uVar46 = uVar46 - 0x80;
          puVar50 = puVar49;
          puVar53 = puVar52;
        } while ((uVar46 & 0xffffff80) != 0);
        puVar50 = puVar49;
        puVar53 = puVar52;
        if (0x1f < uVar46) {
          do {
            puVar49 = puVar50 + -8;
            puVar52 = puVar53 + -8;
            uVar3 = puVar50[-7];
            uVar4 = puVar50[-6];
            uVar5 = puVar50[-5];
            uVar6 = puVar50[-4];
            uVar7 = puVar50[-3];
            uVar8 = puVar50[-2];
            uVar9 = puVar50[-1];
            *puVar52 = *puVar49;
            puVar53[-7] = uVar3;
            puVar53[-6] = uVar4;
            puVar53[-5] = uVar5;
            puVar53[-4] = uVar6;
            puVar53[-3] = uVar7;
            puVar53[-2] = uVar8;
            puVar53[-1] = uVar9;
            uVar46 = uVar46 - 0x20;
            puVar50 = puVar49;
            puVar53 = puVar52;
          } while ((uVar46 & 0xffffffe0) != 0);
        }
      }
    }
    for (; (uVar46 & 0xfffffffc) != 0; uVar46 = uVar46 - 4) {
      puVar52 = puVar52 + -1;
      puVar49 = puVar49 + -1;
      *puVar52 = *puVar49;
    }
    for (; uVar46 != 0; uVar46 = uVar46 - 1) {
      puVar52 = (undefined4 *)((int)puVar52 - 1);
      puVar49 = (undefined4 *)((int)puVar49 + -1);
      *(undefined1 *)puVar52 = *(undefined1 *)puVar49;
    }
    return CONCAT44(uVar47,param_1);
  }
  uVar46 = param_3;
  puVar51 = param_1;
  if (0x1f < param_3) {
    if (param_3 < 0x80) {
      if ((DAT_0041a200 >> 1 & 1) != 0) {
LAB_004136ed:
        if (uVar46 == 0) goto LAB_00413750;
        for (param_3 = uVar46 >> 5; param_3 != 0; param_3 = param_3 - 1) {
          uVar47 = param_2[1];
          uVar54 = param_2[2];
          uVar2 = param_2[3];
          uVar34 = param_2[4];
          uVar35 = param_2[5];
          uVar36 = param_2[6];
          uVar37 = param_2[7];
          *puVar51 = *param_2;
          puVar51[1] = uVar47;
          puVar51[2] = uVar54;
          puVar51[3] = uVar2;
          puVar51[4] = uVar34;
          puVar51[5] = uVar35;
          puVar51[6] = uVar36;
          puVar51[7] = uVar37;
          param_2 = param_2 + 8;
          puVar51 = puVar51 + 8;
        }
        goto LAB_0041371b;
      }
LAB_00413447:
      uVar46 = (uint)param_1 & 3;
      while (uVar46 != 0) {
        *(char *)puVar51 = (char)*param_2;
        param_3 = param_3 - 1;
        param_2 = (uint *)((int)param_2 + 1);
        puVar51 = (uint *)((int)puVar51 + 1);
        uVar46 = (uint)puVar51 & 3;
      }
    }
    else {
      if ((DAT_0041ac28 >> 1 & 1) != 0) {
        for (; uVar46 != 0; uVar46 = uVar46 - 1) {
          *(char *)puVar51 = (char)*param_2;
          param_2 = (uint *)((int)param_2 + 1);
          puVar51 = (uint *)((int)puVar51 + 1);
        }
        return CONCAT44(param_3,param_1);
      }
      if (((((uint)param_1 ^ (uint)param_2) & 0xf) == 0) && ((DAT_0041a200 >> 1 & 1) != 0)) {
        if (((uint)param_2 & 0xf) != 0) {
          uVar47 = 0x10 - ((uint)param_2 & 0xf);
          param_3 = param_3 - uVar47;
          for (uVar46 = uVar47 & 3; uVar46 != 0; uVar46 = uVar46 - 1) {
            *(char *)puVar51 = (char)*param_2;
            param_2 = (uint *)((int)param_2 + 1);
            puVar51 = (uint *)((int)puVar51 + 1);
          }
          for (uVar47 = uVar47 >> 2; uVar47 != 0; uVar47 = uVar47 - 1) {
            *puVar51 = *param_2;
            param_2 = param_2 + 1;
            puVar51 = puVar51 + 1;
          }
        }
        uVar46 = param_3 & 0x7f;
        for (param_3 = param_3 >> 7; param_3 != 0; param_3 = param_3 - 1) {
          uVar47 = param_2[1];
          uVar54 = param_2[2];
          uVar2 = param_2[3];
          uVar34 = param_2[4];
          uVar35 = param_2[5];
          uVar36 = param_2[6];
          uVar37 = param_2[7];
          uVar38 = param_2[8];
          uVar39 = param_2[9];
          uVar40 = param_2[10];
          uVar41 = param_2[0xb];
          uVar42 = param_2[0xc];
          uVar43 = param_2[0xd];
          uVar44 = param_2[0xe];
          uVar45 = param_2[0xf];
          *puVar51 = *param_2;
          puVar51[1] = uVar47;
          puVar51[2] = uVar54;
          puVar51[3] = uVar2;
          puVar51[4] = uVar34;
          puVar51[5] = uVar35;
          puVar51[6] = uVar36;
          puVar51[7] = uVar37;
          puVar51[8] = uVar38;
          puVar51[9] = uVar39;
          puVar51[10] = uVar40;
          puVar51[0xb] = uVar41;
          puVar51[0xc] = uVar42;
          puVar51[0xd] = uVar43;
          puVar51[0xe] = uVar44;
          puVar51[0xf] = uVar45;
          uVar47 = param_2[0x11];
          uVar54 = param_2[0x12];
          uVar2 = param_2[0x13];
          uVar34 = param_2[0x14];
          uVar35 = param_2[0x15];
          uVar36 = param_2[0x16];
          uVar37 = param_2[0x17];
          uVar38 = param_2[0x18];
          uVar39 = param_2[0x19];
          uVar40 = param_2[0x1a];
          uVar41 = param_2[0x1b];
          uVar42 = param_2[0x1c];
          uVar43 = param_2[0x1d];
          uVar44 = param_2[0x1e];
          uVar45 = param_2[0x1f];
          puVar51[0x10] = param_2[0x10];
          puVar51[0x11] = uVar47;
          puVar51[0x12] = uVar54;
          puVar51[0x13] = uVar2;
          puVar51[0x14] = uVar34;
          puVar51[0x15] = uVar35;
          puVar51[0x16] = uVar36;
          puVar51[0x17] = uVar37;
          puVar51[0x18] = uVar38;
          puVar51[0x19] = uVar39;
          puVar51[0x1a] = uVar40;
          puVar51[0x1b] = uVar41;
          puVar51[0x1c] = uVar42;
          puVar51[0x1d] = uVar43;
          puVar51[0x1e] = uVar44;
          puVar51[0x1f] = uVar45;
          param_2 = param_2 + 0x20;
          puVar51 = puVar51 + 0x20;
        }
        goto LAB_004136ed;
      }
      if (((DAT_0041ac28 & 1) == 0) || (((uint)param_1 & 3) != 0)) goto LAB_00413447;
      if (((uint)param_2 & 3) == 0) {
        if (((uint)param_1 >> 2 & 1) != 0) {
          uVar46 = *param_2;
          param_3 = param_3 - 4;
          param_2 = param_2 + 1;
          *param_1 = uVar46;
          param_1 = param_1 + 1;
        }
        if (((uint)param_1 >> 3 & 1) != 0) {
          uVar1 = *(undefined8 *)param_2;
          param_3 = param_3 - 8;
          param_2 = param_2 + 2;
          *(undefined8 *)param_1 = uVar1;
          param_1 = param_1 + 2;
        }
        if (((uint)param_2 & 7) == 0) {
          puVar51 = param_2 + -2;
          uVar46 = *param_2;
          uVar47 = param_2[1];
          do {
            puVar48 = puVar51;
            uVar34 = puVar48[8];
            uVar35 = puVar48[9];
            param_3 = param_3 - 0x30;
            uVar36 = puVar48[6];
            uVar37 = puVar48[7];
            uVar38 = puVar48[8];
            uVar39 = puVar48[9];
            uVar54 = puVar48[0xe];
            uVar2 = puVar48[0xf];
            uVar40 = puVar48[10];
            uVar41 = puVar48[0xb];
            uVar42 = puVar48[0xc];
            uVar43 = puVar48[0xd];
            param_1[2] = uVar46;
            param_1[3] = uVar47;
            param_1[4] = uVar34;
            param_1[5] = uVar35;
            param_1[6] = uVar36;
            param_1[7] = uVar37;
            param_1[8] = uVar38;
            param_1[9] = uVar39;
            param_1[10] = uVar40;
            param_1[0xb] = uVar41;
            param_1[0xc] = uVar42;
            param_1[0xd] = uVar43;
            param_1 = param_1 + 0xc;
            puVar51 = puVar48 + 0xc;
            uVar46 = uVar54;
            uVar47 = uVar2;
          } while (0x2f < (int)param_3);
          puVar48 = puVar48 + 0xe;
        }
        else if (((uint)param_2 >> 3 & 1) == 0) {
          puVar51 = param_2 + -1;
          uVar46 = *param_2;
          uVar47 = param_2[1];
          uVar54 = param_2[2];
          do {
            puVar48 = puVar51;
            uVar36 = puVar48[8];
            param_3 = param_3 - 0x30;
            uVar37 = puVar48[5];
            uVar38 = puVar48[6];
            uVar39 = puVar48[7];
            uVar40 = puVar48[8];
            uVar2 = puVar48[0xd];
            uVar34 = puVar48[0xe];
            uVar35 = puVar48[0xf];
            uVar41 = puVar48[9];
            uVar42 = puVar48[10];
            uVar43 = puVar48[0xb];
            uVar44 = puVar48[0xc];
            param_1[1] = uVar46;
            param_1[2] = uVar47;
            param_1[3] = uVar54;
            param_1[4] = uVar36;
            param_1[5] = uVar37;
            param_1[6] = uVar38;
            param_1[7] = uVar39;
            param_1[8] = uVar40;
            param_1[9] = uVar41;
            param_1[10] = uVar42;
            param_1[0xb] = uVar43;
            param_1[0xc] = uVar44;
            param_1 = param_1 + 0xc;
            puVar51 = puVar48 + 0xc;
            uVar46 = uVar2;
            uVar47 = uVar34;
            uVar54 = uVar35;
          } while (0x2f < (int)param_3);
          puVar48 = puVar48 + 0xd;
        }
        else {
          puVar51 = param_2 + -3;
          uVar46 = *param_2;
          do {
            puVar48 = puVar51;
            uVar54 = puVar48[8];
            uVar2 = puVar48[9];
            uVar34 = puVar48[10];
            param_3 = param_3 - 0x30;
            uVar35 = puVar48[7];
            uVar36 = puVar48[8];
            uVar37 = puVar48[9];
            uVar38 = puVar48[10];
            uVar47 = puVar48[0xf];
            uVar39 = puVar48[0xb];
            uVar40 = puVar48[0xc];
            uVar41 = puVar48[0xd];
            uVar42 = puVar48[0xe];
            param_1[3] = uVar46;
            param_1[4] = uVar54;
            param_1[5] = uVar2;
            param_1[6] = uVar34;
            param_1[7] = uVar35;
            param_1[8] = uVar36;
            param_1[9] = uVar37;
            param_1[10] = uVar38;
            param_1[0xb] = uVar39;
            param_1[0xc] = uVar40;
            param_1[0xd] = uVar41;
            param_1[0xe] = uVar42;
            param_1 = param_1 + 0xc;
            puVar51 = puVar48 + 0xc;
            uVar46 = uVar47;
          } while (0x2f < (int)param_3);
          puVar48 = puVar48 + 0xf;
        }
        for (; 0xf < (int)param_3; param_3 = param_3 - 0x10) {
          uVar46 = *puVar48;
          uVar47 = puVar48[1];
          uVar54 = puVar48[2];
          uVar2 = puVar48[3];
          puVar48 = puVar48 + 4;
          *param_1 = uVar46;
          param_1[1] = uVar47;
          param_1[2] = uVar54;
          param_1[3] = uVar2;
          param_1 = param_1 + 4;
        }
        if ((param_3 >> 2 & 1) != 0) {
          uVar46 = *puVar48;
          param_3 = param_3 - 4;
          puVar48 = puVar48 + 1;
          *param_1 = uVar46;
          param_1 = param_1 + 1;
        }
        if ((param_3 >> 3 & 1) != 0) {
          param_3 = param_3 - 8;
          *(undefined8 *)param_1 = *(undefined8 *)puVar48;
        }
                    // WARNING: Could not recover jumptable at 0x00413445. Too many branches
                    // WARNING: Treating indirect jump as call
        uVar55 = (*(code *)(&switchD_00413475::switchdataD_00413484)[param_3])();
        return uVar55;
      }
    }
    uVar46 = param_3;
    if (0x1f < param_3) {
      for (uVar46 = param_3 >> 2; uVar46 != 0; uVar46 = uVar46 - 1) {
        *puVar51 = *param_2;
        param_2 = param_2 + 1;
        puVar51 = puVar51 + 1;
      }
      switch(param_3 & 3) {
      case 0:
        return CONCAT44(param_3,param_1) & 0x3ffffffff;
      case 1:
        *(char *)puVar51 = (char)*param_2;
        return CONCAT44(param_3,param_1) & 0x3ffffffff;
      case 2:
        *(char *)puVar51 = (char)*param_2;
        *(undefined1 *)((int)puVar51 + 1) = *(undefined1 *)((int)param_2 + 1);
        return CONCAT44(param_3,param_1) & 0x3ffffffff;
      case 3:
        *(char *)puVar51 = (char)*param_2;
        *(undefined1 *)((int)puVar51 + 1) = *(undefined1 *)((int)param_2 + 1);
        *(undefined1 *)((int)puVar51 + 2) = *(undefined1 *)((int)param_2 + 2);
        return CONCAT44(param_3,param_1) & 0x3ffffffff;
      }
    }
  }
LAB_0041371b:
  if ((uVar46 & 0x1f) != 0) {
    for (uVar47 = (uVar46 & 0x1f) >> 2; uVar47 != 0; uVar47 = uVar47 - 1) {
      param_3 = *param_2;
      *puVar51 = param_3;
      puVar51 = puVar51 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar46 = uVar46 & 3; uVar46 != 0; uVar46 = uVar46 - 1) {
      *(char *)puVar51 = (char)*param_2;
      param_2 = (uint *)((int)param_2 + 1);
      puVar51 = (uint *)((int)puVar51 + 1);
    }
  }
LAB_00413750:
  return CONCAT44(param_3,param_1);
}



undefined1 (*) [16] __cdecl FUN_00413e50(undefined1 (*param_1) [16],byte param_2)

{
  byte bVar1;
  undefined1 *puVar2;
  uint uVar3;
  undefined1 (*pauVar4) [16];
  uint uVar5;
  int iVar6;
  undefined1 (*pauVar7) [16];
  char *pcVar8;
  byte *pbVar9;
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined1 auVar13 [16];
  undefined1 auVar14 [16];
  byte *pbVar10;
  
  if (DAT_0041ac24 != 0) {
    if (DAT_0041ac24 < 2) {
      auVar14 = pshuflw(ZEXT216(CONCAT11(param_2,param_2)),ZEXT216(CONCAT11(param_2,param_2)),0);
      uVar3 = -1 << (sbyte)((uint)param_1 & 0xf);
      pcVar8 = (char *)((int)param_1 - ((uint)param_1 & 0xf));
      pauVar7 = (undefined1 (*) [16])0x0;
      while( true ) {
        auVar13[0] = -(*pcVar8 == '\0');
        auVar13[1] = -(pcVar8[1] == '\0');
        auVar13[2] = -(pcVar8[2] == '\0');
        auVar13[3] = -(pcVar8[3] == '\0');
        auVar13[4] = -(pcVar8[4] == '\0');
        auVar13[5] = -(pcVar8[5] == '\0');
        auVar13[6] = -(pcVar8[6] == '\0');
        auVar13[7] = -(pcVar8[7] == '\0');
        auVar13[8] = -(pcVar8[8] == '\0');
        auVar13[9] = -(pcVar8[9] == '\0');
        auVar13[10] = -(pcVar8[10] == '\0');
        auVar13[0xb] = -(pcVar8[0xb] == '\0');
        auVar13[0xc] = -(pcVar8[0xc] == '\0');
        auVar13[0xd] = -(pcVar8[0xd] == '\0');
        auVar13[0xe] = -(pcVar8[0xe] == '\0');
        auVar13[0xf] = -(pcVar8[0xf] == '\0');
        auVar12[0] = -(*pcVar8 == auVar14[0]);
        auVar12[1] = -(pcVar8[1] == auVar14[1]);
        auVar12[2] = -(pcVar8[2] == auVar14[2]);
        auVar12[3] = -(pcVar8[3] == auVar14[3]);
        auVar12[4] = -(pcVar8[4] == auVar14[4]);
        auVar12[5] = -(pcVar8[5] == auVar14[5]);
        auVar12[6] = -(pcVar8[6] == auVar14[6]);
        auVar12[7] = -(pcVar8[7] == auVar14[7]);
        auVar12[8] = -(pcVar8[8] == auVar14[0]);
        auVar12[9] = -(pcVar8[9] == auVar14[1]);
        auVar12[10] = -(pcVar8[10] == auVar14[2]);
        auVar12[0xb] = -(pcVar8[0xb] == auVar14[3]);
        auVar12[0xc] = -(pcVar8[0xc] == auVar14[4]);
        auVar12[0xd] = -(pcVar8[0xd] == auVar14[5]);
        auVar12[0xe] = -(pcVar8[0xe] == auVar14[6]);
        auVar12[0xf] = -(pcVar8[0xf] == auVar14[7]);
        uVar5 = (ushort)((ushort)(SUB161(auVar13 >> 7,0) & 1) |
                         (ushort)(SUB161(auVar13 >> 0xf,0) & 1) << 1 |
                         (ushort)(SUB161(auVar13 >> 0x17,0) & 1) << 2 |
                         (ushort)(SUB161(auVar13 >> 0x1f,0) & 1) << 3 |
                         (ushort)(SUB161(auVar13 >> 0x27,0) & 1) << 4 |
                         (ushort)(SUB161(auVar13 >> 0x2f,0) & 1) << 5 |
                         (ushort)(SUB161(auVar13 >> 0x37,0) & 1) << 6 |
                         (ushort)(SUB161(auVar13 >> 0x3f,0) & 1) << 7 |
                         (ushort)(SUB161(auVar13 >> 0x47,0) & 1) << 8 |
                         (ushort)(SUB161(auVar13 >> 0x4f,0) & 1) << 9 |
                         (ushort)(SUB161(auVar13 >> 0x57,0) & 1) << 10 |
                         (ushort)(SUB161(auVar13 >> 0x5f,0) & 1) << 0xb |
                         (ushort)(SUB161(auVar13 >> 0x67,0) & 1) << 0xc |
                         (ushort)(SUB161(auVar13 >> 0x6f,0) & 1) << 0xd |
                         (ushort)(SUB161(auVar13 >> 0x77,0) & 1) << 0xe |
                        (ushort)(auVar13[0xf] >> 7) << 0xf) & uVar3;
        if (uVar5 != 0) break;
        uVar3 = (ushort)((ushort)(SUB161(auVar12 >> 7,0) & 1) |
                         (ushort)(SUB161(auVar12 >> 0xf,0) & 1) << 1 |
                         (ushort)(SUB161(auVar12 >> 0x17,0) & 1) << 2 |
                         (ushort)(SUB161(auVar12 >> 0x1f,0) & 1) << 3 |
                         (ushort)(SUB161(auVar12 >> 0x27,0) & 1) << 4 |
                         (ushort)(SUB161(auVar12 >> 0x2f,0) & 1) << 5 |
                         (ushort)(SUB161(auVar12 >> 0x37,0) & 1) << 6 |
                         (ushort)(SUB161(auVar12 >> 0x3f,0) & 1) << 7 |
                         (ushort)(SUB161(auVar12 >> 0x47,0) & 1) << 8 |
                         (ushort)(SUB161(auVar12 >> 0x4f,0) & 1) << 9 |
                         (ushort)(SUB161(auVar12 >> 0x57,0) & 1) << 10 |
                         (ushort)(SUB161(auVar12 >> 0x5f,0) & 1) << 0xb |
                         (ushort)(SUB161(auVar12 >> 0x67,0) & 1) << 0xc |
                         (ushort)(SUB161(auVar12 >> 0x6f,0) & 1) << 0xd |
                         (ushort)(SUB161(auVar12 >> 0x77,0) & 1) << 0xe |
                        (ushort)(auVar12[0xf] >> 7) << 0xf) & uVar3;
        iVar6 = 0x1f;
        if (uVar3 != 0) {
          for (; uVar3 >> iVar6 == 0; iVar6 = iVar6 + -1) {
          }
        }
        if (uVar3 != 0) {
          pauVar7 = (undefined1 (*) [16])(pcVar8 + iVar6);
        }
        uVar3 = 0xffffffff;
        pcVar8 = pcVar8 + 0x10;
      }
      uVar3 = (uVar5 * 2 & uVar5 * -2) - 1 &
              (ushort)((ushort)(SUB161(auVar12 >> 7,0) & 1) |
                       (ushort)(SUB161(auVar12 >> 0xf,0) & 1) << 1 |
                       (ushort)(SUB161(auVar12 >> 0x17,0) & 1) << 2 |
                       (ushort)(SUB161(auVar12 >> 0x1f,0) & 1) << 3 |
                       (ushort)(SUB161(auVar12 >> 0x27,0) & 1) << 4 |
                       (ushort)(SUB161(auVar12 >> 0x2f,0) & 1) << 5 |
                       (ushort)(SUB161(auVar12 >> 0x37,0) & 1) << 6 |
                       (ushort)(SUB161(auVar12 >> 0x3f,0) & 1) << 7 |
                       (ushort)(SUB161(auVar12 >> 0x47,0) & 1) << 8 |
                       (ushort)(SUB161(auVar12 >> 0x4f,0) & 1) << 9 |
                       (ushort)(SUB161(auVar12 >> 0x57,0) & 1) << 10 |
                       (ushort)(SUB161(auVar12 >> 0x5f,0) & 1) << 0xb |
                       (ushort)(SUB161(auVar12 >> 0x67,0) & 1) << 0xc |
                       (ushort)(SUB161(auVar12 >> 0x6f,0) & 1) << 0xd |
                       (ushort)(SUB161(auVar12 >> 0x77,0) & 1) << 0xe |
                      (ushort)(auVar12[0xf] >> 7) << 0xf) & uVar3;
      iVar6 = 0x1f;
      if (uVar3 != 0) {
        for (; uVar3 >> iVar6 == 0; iVar6 = iVar6 + -1) {
        }
      }
      pauVar4 = (undefined1 (*) [16])(pcVar8 + iVar6);
      if (uVar3 == 0) {
        pauVar4 = pauVar7;
      }
      return pauVar4;
    }
    uVar3 = (uint)param_2;
    if (uVar3 == 0) {
      pcVar8 = (char *)((uint)param_1 & 0xfffffff0);
      auVar14[0] = -(*pcVar8 == '\0');
      auVar14[1] = -(pcVar8[1] == '\0');
      auVar14[2] = -(pcVar8[2] == '\0');
      auVar14[3] = -(pcVar8[3] == '\0');
      auVar14[4] = -(pcVar8[4] == '\0');
      auVar14[5] = -(pcVar8[5] == '\0');
      auVar14[6] = -(pcVar8[6] == '\0');
      auVar14[7] = -(pcVar8[7] == '\0');
      auVar14[8] = -(pcVar8[8] == '\0');
      auVar14[9] = -(pcVar8[9] == '\0');
      auVar14[10] = -(pcVar8[10] == '\0');
      auVar14[0xb] = -(pcVar8[0xb] == '\0');
      auVar14[0xc] = -(pcVar8[0xc] == '\0');
      auVar14[0xd] = -(pcVar8[0xd] == '\0');
      auVar14[0xe] = -(pcVar8[0xe] == '\0');
      auVar14[0xf] = -(pcVar8[0xf] == '\0');
      uVar3 = (uint)(ushort)((ushort)(SUB161(auVar14 >> 7,0) & 1) |
                             (ushort)(SUB161(auVar14 >> 0xf,0) & 1) << 1 |
                             (ushort)(SUB161(auVar14 >> 0x17,0) & 1) << 2 |
                             (ushort)(SUB161(auVar14 >> 0x1f,0) & 1) << 3 |
                             (ushort)(SUB161(auVar14 >> 0x27,0) & 1) << 4 |
                             (ushort)(SUB161(auVar14 >> 0x2f,0) & 1) << 5 |
                             (ushort)(SUB161(auVar14 >> 0x37,0) & 1) << 6 |
                             (ushort)(SUB161(auVar14 >> 0x3f,0) & 1) << 7 |
                             (ushort)(SUB161(auVar14 >> 0x47,0) & 1) << 8 |
                             (ushort)(SUB161(auVar14 >> 0x4f,0) & 1) << 9 |
                             (ushort)(SUB161(auVar14 >> 0x57,0) & 1) << 10 |
                             (ushort)(SUB161(auVar14 >> 0x5f,0) & 1) << 0xb |
                             (ushort)(SUB161(auVar14 >> 0x67,0) & 1) << 0xc |
                             (ushort)(SUB161(auVar14 >> 0x6f,0) & 1) << 0xd |
                             (ushort)(SUB161(auVar14 >> 0x77,0) & 1) << 0xe |
                            (ushort)(auVar14[0xf] >> 7) << 0xf) & -1 << ((byte)param_1 & 0xf);
      while (uVar3 == 0) {
        auVar11[0] = -(pcVar8[0x10] == '\0');
        auVar11[1] = -(pcVar8[0x11] == '\0');
        auVar11[2] = -(pcVar8[0x12] == '\0');
        auVar11[3] = -(pcVar8[0x13] == '\0');
        auVar11[4] = -(pcVar8[0x14] == '\0');
        auVar11[5] = -(pcVar8[0x15] == '\0');
        auVar11[6] = -(pcVar8[0x16] == '\0');
        auVar11[7] = -(pcVar8[0x17] == '\0');
        auVar11[8] = -(pcVar8[0x18] == '\0');
        auVar11[9] = -(pcVar8[0x19] == '\0');
        auVar11[10] = -(pcVar8[0x1a] == '\0');
        auVar11[0xb] = -(pcVar8[0x1b] == '\0');
        auVar11[0xc] = -(pcVar8[0x1c] == '\0');
        auVar11[0xd] = -(pcVar8[0x1d] == '\0');
        auVar11[0xe] = -(pcVar8[0x1e] == '\0');
        auVar11[0xf] = -(pcVar8[0x1f] == '\0');
        pcVar8 = pcVar8 + 0x10;
        uVar3 = (uint)(ushort)((ushort)(SUB161(auVar11 >> 7,0) & 1) |
                               (ushort)(SUB161(auVar11 >> 0xf,0) & 1) << 1 |
                               (ushort)(SUB161(auVar11 >> 0x17,0) & 1) << 2 |
                               (ushort)(SUB161(auVar11 >> 0x1f,0) & 1) << 3 |
                               (ushort)(SUB161(auVar11 >> 0x27,0) & 1) << 4 |
                               (ushort)(SUB161(auVar11 >> 0x2f,0) & 1) << 5 |
                               (ushort)(SUB161(auVar11 >> 0x37,0) & 1) << 6 |
                               (ushort)(SUB161(auVar11 >> 0x3f,0) & 1) << 7 |
                               (ushort)(SUB161(auVar11 >> 0x47,0) & 1) << 8 |
                               (ushort)(SUB161(auVar11 >> 0x4f,0) & 1) << 9 |
                               (ushort)(SUB161(auVar11 >> 0x57,0) & 1) << 10 |
                               (ushort)(SUB161(auVar11 >> 0x5f,0) & 1) << 0xb |
                               (ushort)(SUB161(auVar11 >> 0x67,0) & 1) << 0xc |
                               (ushort)(SUB161(auVar11 >> 0x6f,0) & 1) << 0xd |
                               (ushort)(SUB161(auVar11 >> 0x77,0) & 1) << 0xe |
                              (ushort)(auVar11[0xf] >> 7) << 0xf);
      }
      iVar6 = 0;
      if (uVar3 != 0) {
        for (; (uVar3 >> iVar6 & 1) == 0; iVar6 = iVar6 + 1) {
        }
      }
      pauVar7 = (undefined1 (*) [16])(pcVar8 + iVar6);
    }
    else {
      pauVar7 = (undefined1 (*) [16])0x0;
      uVar5 = (uint)param_1 & 0xf;
      while (uVar5 != 0) {
        if ((byte)(*param_1)[0] == uVar3) {
          pauVar7 = param_1;
        }
        if ((byte)(*param_1)[0] == 0) {
          return pauVar7;
        }
        param_1 = (undefined1 (*) [16])(*param_1 + 1);
        uVar5 = (uint)param_1 & 0xf;
      }
      do {
        pauVar4 = param_1 + 1;
        iVar6 = pcmpistri(ZEXT416(uVar3),*param_1,0x40);
        if ((undefined1 (*) [16])0xffffffef < param_1) {
          pauVar7 = (undefined1 (*) [16])(*param_1 + iVar6);
        }
        param_1 = pauVar4;
      } while (pauVar4 != (undefined1 (*) [16])0x0);
    }
    return pauVar7;
  }
  iVar6 = -1;
  do {
    pauVar7 = param_1;
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    pauVar7 = (undefined1 (*) [16])(*param_1 + 1);
    puVar2 = *param_1;
    param_1 = pauVar7;
  } while (*puVar2 != '\0');
  iVar6 = -(iVar6 + 1);
  pbVar10 = pauVar7[-1] + 0xf;
  do {
    pbVar9 = pbVar10;
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    pbVar9 = pbVar10 + -1;
    bVar1 = *pbVar10;
    pbVar10 = pbVar9;
  } while (param_2 != bVar1);
  pauVar7 = (undefined1 (*) [16])(pbVar9 + 1);
  if ((*pauVar7)[0] != param_2) {
    pauVar7 = (undefined1 (*) [16])0x0;
  }
  return pauVar7;
}


