#include <Windows.h>
#include <Psapi.h>

#ifndef ZwQuerySystemInformation_H
#define ZwQuerySystemInformation_H

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,// 0 Y N
	SystemProcessorInformation,// 1 Y N
	SystemPerformanceInformation,// 2 Y N
	SystemTimeOfDayInformation,// 3 Y N
	SystemNotImplemented1,// 4 Y N // SystemPathInformation
	SystemProcessesAndThreadsInformation,// 5 Y N
	SystemCallCounts,// 6 Y N
	SystemConfigurationInformation,// 7 Y N
	SystemProcessorTimes,// 8 Y N
	SystemGlobalFlag,// 9 Y Y
	SystemNotImplemented2,// 10 YN // SystemCallTimeInformation
	SystemModuleInformation,// 11 YN
	SystemLockInformation,// 12 YN
	SystemNotImplemented3,// 13 YN // SystemStackTraceInformation
	SystemNotImplemented4,// 14 YN // SystemPagedPoolInformation
	SystemNotImplemented5,// 15 YN // SystemNonPagedPoolInformation
	SystemHandleInformation,// 16 YN
	SystemObjectInformation,// 17 YN
	SystemPagefileInformation,// 18 YN
	SystemInstructionEmulationCounts,// 19 YN
	SystemInvalidInfoClass1,// 20
	SystemCacheInformation,// 21 YY
	SystemPoolTagInformation,// 22 YN
	SystemProcessorStatistics,// 23 YN
	SystemDpcInformation,// 24 YY
	SystemNotImplemented6,// 25 YN // SystemFullMemoryInformation
	SystemLoadImage,// 26 NY // SystemLoadGdiDriverInformation
	SystemUnloadImage,// 27 NY
	SystemTimeAdjustment,// 28 YY
	SystemNotImplemented7,// 29 YN // SystemSummaryMemoryInformation
	SystemNotImplemented8,// 30 YN // SystemNextEventIdInformation
	SystemNotImplemented9,// 31 YN // SystemEventIdsInformation
	SystemCrashDumpInformation,// 32 YN
	SystemExceptionInformation,// 33 YN
	SystemCrashDumpStateInformation,// 34 YY/N
	SystemKernelDebuggerInformation,// 35 YN
	SystemContextSwitchInformation,// 36 YN
	SystemRegistryQuotaInformation,// 37 YY
	SystemLoadAndCallImage,// 38 NY // SystemExtendServiceTableInformation
	SystemPrioritySeparation,// 39 NY
	SystemNotImplemented10,// 40 YN // SystemPlugPlayBusInformation
	SystemNotImplemented11,// 41 YN // SystemDockInformation
	SystemInvalidInfoClass2,// 42 // SystemPowerInformation
	SystemInvalidInfoClass3,// 43 // SystemProcessorSpeedInformation
	SystemTimeZoneInformation,// 44 YN
	SystemLookasideInformation,// 45 YN
	SystemSetTimeSlipEvent,// 46 NY
	SystemCreateSession,// 47 NY
	SystemDeleteSession,// 48 NY
	SystemInvalidInfoClass4,// 49
	SystemRangeStartInformation,// 50 YN
	SystemVerifierInformation,// 51 YY
	SystemAddVerifier,// 52 NY
	SystemSessionProcessesInformation// 53 YN
} SYSTEM_INFORMATION_CLASS;
typedef enum _THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
}THREAD_STATE;
typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVertualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel
}KWAIT_REASON;
typedef struct _LSA_UNICODE_STRING
{
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR   Buffer;
}LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef LSA_UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;
typedef LONG KPRIORITY;
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;
typedef struct _VM_COUNTERS
{
	ULONG PeakVirtualSize;                  //虚拟存储峰值大小；
	ULONG VirtualSize;                      //虚拟存储大小；
	ULONG PageFaultCount;                   //页故障数目；
	ULONG PeakWorkingSetSize;               //工作集峰值大小；
	ULONG WorkingSetSize;                   //工作集大小；
	ULONG QuotaPeakPagedPoolUsage;          //分页池使用配额峰值；
	ULONG QuotaPagedPoolUsage;              //分页池使用配额；
	ULONG QuotaPeakNonPagedPoolUsage;       //非分页池使用配额峰值；
	ULONG QuotaNonPagedPoolUsage;           //非分页池使用配额；
	ULONG PagefileUsage;                    //页文件使用情况；
	ULONG PeakPagefileUsage;                //页文件使用峰值；
}VM_COUNTERS, *PVM_COUNTERS;
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;               //CPU内核模式使用时间；
	LARGE_INTEGER UserTime;                 //CPU用户模式使用时间；
	LARGE_INTEGER CreateTime;               //线程创建时间；
	ULONG         WaitTime;                 //等待时间；
	PVOID         StartAddress;             //线程开始的虚拟地址；
	CLIENT_ID     ClientId;                 //线程标识符；
	KPRIORITY     Priority;                 //线程优先级；
	KPRIORITY     BasePriority;             //基本优先级；
	ULONG         ContextSwitchCount;       //环境切换数目；
	THREAD_STATE  State;                    //当前状态；
	KWAIT_REASON  WaitReason;               //等待原因；
}SYSTEM_THREADS, *PSYSTEM_THREADS;
typedef struct _SYSTEM_PROCESSES
{
	ULONG          NextEntryDelta;          //构成结构序列的偏移量；
	ULONG          ThreadCount;             //线程数目；
	ULONG          Reserved1[6];
	LARGE_INTEGER  CreateTime;              //创建时间；
	LARGE_INTEGER  UserTime;                //用户模式(Ring 3)的CPU时间；
	LARGE_INTEGER  KernelTime;              //内核模式(Ring 0)的CPU时间；
	UNICODE_STRING ProcessName;             //进程名称；
	KPRIORITY      BasePriority;            //进程优先权；
	ULONG          ProcessId;               //进程标识符；
	ULONG          InheritedFromProcessId;  //父进程的标识符；
	ULONG          HandleCount;             //句柄数目；
	ULONG          Reserved2[2];
	VM_COUNTERS    VmCounters;              //虚拟存储器的结构，见下；
	IO_COUNTERS    IoCounters;              //IO计数结构，见下；
	SYSTEM_THREADS Threads[1];              //进程相关线程的结构数组，见下；
}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREAD_INFORMATION           Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


#endif // !ZwQuerySystemInformation_H