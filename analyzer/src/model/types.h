#pragma once
#include "model/stack_trie.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ttds {

// ---- Output record types. Binary layouts are fixed; see out/writer.cpp and client/trace-reader.js.

enum class EventKind : uint8_t
{
    Alloc = 1, Free = 2, ReAlloc = 3, HeapCreate = 4, HeapDestroy = 5, FreeUnknown = 7, AllocFailed = 8,
    Reserve = 16, Commit = 17, Decommit = 18, Release = 19, Protect = 20, MapView = 21, UnmapView = 22,
    ModuleLoad = 32, ModuleUnload = 33, ThreadCreate = 34, ThreadExit = 35, Marker = 36, DirectSyscall = 37,
};

enum EventFlags : uint8_t
{
    EvNested      = 0x01, // made from inside another hooked call (e.g. heap -> VM)
    EvOutReadback = 0x02, // an out-param came from a memory read-back rather than a computation
    EvOutUnknown  = 0x04, // an out-param could not be recovered
    EvUnwound     = 0x08, // the call never returned normally
    EvFailed      = 0x10, // the call failed (NULL / FALSE / NTSTATUS error)
    EvCrossThread = 0x20, // freed on a different thread than it was allocated on
    EvRemote      = 0x40, // targets another process
    EvExtra       = 0x80, // kind-specific: Reserve=also committed, FreeUnknown=double free, Alloc=superseded a live block
};

#pragma pack(push, 1)
struct Event          // 32 bytes
{
    uint8_t  kind;
    uint8_t  flags;
    uint16_t thread;
    uint32_t id;      // block / region / module / thread / marker index
    uint64_t addr;
    uint64_t size;
    uint32_t stack;   // StackTrie node or kNone
    uint32_t aux;     // heap id (heap events) / protection (VM events)
};
static_assert(sizeof(Event) == 32);

enum BlockFlags : uint32_t
{
    BlkPreTrace     = 0x01, // allocated before the recording started (first seen being freed)
    BlkSizeUnknown  = 0x02,
    BlkImplicitFree = 0x04, // freed by RtlDestroyHeap
    BlkSuperseded   = 0x08, // a new allocation overlapped it while live (a free was missed)
    BlkInPlace      = 0x10, // realloc result at the same address as its predecessor
    BlkRealloced    = 0x20, // ended by a realloc (its successor links back via prev)
    BlkCrossThread  = 0x40,
    BlkFreeUnwound  = 0x80,
};

struct Block          // 48 bytes
{
    uint64_t addr;
    uint64_t size;
    uint32_t heap;
    uint32_t allocEvt;  // kNone = before the trace
    uint32_t freeEvt;   // kNone = still live at the end of the trace
    uint32_t allocStack;
    uint32_t freeStack;
    uint32_t prev;      // predecessor in a realloc chain
    uint32_t flags;
    uint16_t allocThread;
    uint16_t freeThread;
};
static_assert(sizeof(Block) == 48);

enum class RegionKind : uint32_t { Private = 0, Mapped = 1, Image = 2, Stack = 3, Heap = 4, Inferred = 5, HeapInferred = 6 };

enum RegionFlags : uint32_t
{
    RgnPreTrace   = 0x01, // existed before the recording
    RgnGrown      = 0x02, // inferred region that was extended
    RgnUnknownEnd = 0x04,
};

struct Region         // 48 bytes
{
    uint64_t base;
    uint64_t size;
    uint32_t kind;
    uint32_t createEvt;
    uint32_t releaseEvt;
    uint32_t heap;       // heap id for heap segments, module index for images, thread index for stacks
    uint32_t createStack;
    uint32_t releaseStack;
    uint32_t flags;
    uint32_t pad;
};
static_assert(sizeof(Region) == 48);

enum class SpanState : uint16_t { Reserved = 1, Committed = 2 };

struct Span           // 40 bytes
{
    uint64_t start;
    uint64_t end;
    uint32_t region;
    uint16_t state;
    uint16_t flags;
    uint32_t protect;
    uint32_t startEvt;  // kNone = before the trace
    uint32_t endEvt;    // kNone = still present at the end
    uint32_t pad;
};
static_assert(sizeof(Span) == 40);

struct Position16 { uint64_t seq; uint64_t steps; };

enum CallRecFlags : uint8_t
{
    CrReturned   = 0x01, // the matching RET was seen
    CrUnwound    = 0x02, // the caller's frame was discarded without a RET
    CrTail       = 0x04, // entered by a jump (import thunk, CFG dispatch, export forwarding by jmp)
    CrSameModule = 0x08, // caller and callee are in the same module
};

// A call into a module export. Times are on the event axis: the call happens between events
// startEvt - 1 and startEvt, at startEvt - 1 + startFrac (fractions spread calls that fall
// between the same two events evenly, in position order).
struct CallRec        // 32 bytes
{
    uint16_t thread;
    uint8_t  flags;
    uint8_t  depth;
    uint32_t callerFrame; // frames.bin index of the return address (caller's code)
    uint32_t callee;      // callees.json index
    uint32_t startEvt;    // first event at or after the CALL (== event count if none)
    uint32_t endEvt;      // first event after the RET, kNone if it never returned
    float    startFrac;
    float    endFrac;
    uint32_t via;         // tail jump: index of the call whose frame this one continued, else kNone
};
static_assert(sizeof(CallRec) == 32);
#pragma pack(pop)

struct CalleeOut
{
    uint64_t    address = 0;
    uint32_t    module = kNone;
    std::string name;
};

enum class HeapKind : uint8_t { Process, Created, PreExisting, Discovered };

struct HeapInfo
{
    uint64_t handle = 0;
    HeapKind kind = HeapKind::Discovered;
    uint32_t createEvt = kNone;
    uint32_t destroyEvt = kNone;
    uint32_t createFlags = 0;
    uint32_t createStack = kNone;
};

struct ThreadOut
{
    uint32_t utid = 0, osTid = 0;
    uint32_t createEvt = kNone, exitEvt = kNone;
    uint64_t stackLow = 0, stackHigh = 0;
    std::string stackSource; // "teb" | "observed"
};

struct ModuleOut
{
    std::string name, path;
    uint64_t base = 0, size = 0;
    uint32_t timestamp = 0, checksum = 0;
    uint32_t loadEvt = kNone, unloadEvt = kNone;
    uint32_t region = kNone;
};

struct MarkerOut
{
    uint32_t evt = kNone;
    uint16_t thread = 0;
    std::string text;
};

struct SeriesOut
{
    uint32_t buckets = 0;
    double   eventsPerBucket = 0;
    // Column name -> values (end-of-bucket unless stated otherwise).
    std::vector<std::pair<std::string, std::vector<double>>> columns;
};

struct QualityOut
{
    uint64_t outComputed = 0, outAtReturn = 0, outReadback = 0, outSeek = 0, outUnknown = 0, oldProtectFromModel = 0;
    uint64_t unwound = 0, neverReturned = 0, unmatchedRets = 0, tailCalls = 0;
    uint64_t superseded = 0, doubleFree = 0, preTraceFrees = 0, nestedSkipped = 0;
    uint64_t failedCalls = 0, remoteCalls = 0, unplacedVm = 0, releaseUnknownRegion = 0;
    uint64_t kernelCalls = 0, directSyscalls = 0, positionOrderViolations = 0;
};

struct CallsOut
{
    bool     recorded = false;       // export calls were captured (analyze --calls exports)
    std::vector<CallRec>   records;  // sorted by start time
    std::vector<CalleeOut> callees;  // exports that were called
    std::vector<uint32_t>  source;   // per record: index in CaptureResult::exportCalls
    std::vector<Position16> positions; // per record: CALL position, RET position (seq = ~0 if none)
    std::vector<uint32_t>  stacks;   // per record: StackTrie node of the caller's stack (kNone if none)
    bool     args = false;           // arguments were decoded (callargs.*)
    uint64_t argsWithSignature = 0, argsHeuristic = 0, argStringsAtReturn = 0, signatures = 0;
    uint64_t tailCalls = 0, unwound = 0, neverReturned = 0, sameModule = 0;
    uint32_t exportModules = 0, exportModulesFromDisk = 0;
    std::vector<std::string> modulesWithoutExports;
};

// Records written to activity.bin / writers.bin (layouts shared with client/trace-reader.js).
#pragma pack(push, 1)
struct ActivityCell   // 20 bytes: writes to one object in one series bucket
{
    uint32_t block;   // kNone for a page of a region
    uint32_t region;  // region holding the object (kNone if unknown)
    uint32_t page;    // page index within the region (kNone for a block)
    uint32_t bucket;
    uint32_t writes;
};
static_assert(sizeof(ActivityCell) == 20);

enum WriterFlags : uint32_t { WrUnbacked = 0x01 }; // some writer ran outside every module

struct WriterRec      // 40 bytes: who wrote one object, over the whole trace
{
    uint32_t block, region, page;
    uint32_t firstFrame, lastFrame; // frames.bin (PC + 1, as frames are return addresses)
    uint32_t firstEvt, lastEvt;     // first event at or after the write
    uint16_t firstThread, lastThread;
    uint32_t writes;
    uint32_t flags;
};
static_assert(sizeof(WriterRec) == 40);
#pragma pack(pop)

// Code that ran from a page written during the trace.
struct WxFinding
{
    uint32_t   region = kNone;
    uint64_t   page = 0;               // page address
    Position16 execPos{}, writePos{};
    uint32_t   execEvt = 0, writeEvt = 0;
    uint16_t   execThread = 0, writeThread = 0;
    uint64_t   execPc = 0, writerPc = 0;
    uint32_t   writerFrame = kNone;
    uint32_t   writerRegion = kNone;   // region holding the writing code (an image region for module code)
    uint64_t   writesBefore = 0;       // writes to the page before it first ran
};

#pragma pack(push, 1)
struct FlowRec        // 16 bytes: writes from code in one region to memory in another, in one bucket
{
    uint32_t bucket;
    uint32_t from;    // region holding the writing code (an image region for module code), or kNone
    uint32_t to;      // region written, or kNone
    uint32_t writes;
};
static_assert(sizeof(FlowRec) == 16);
#pragma pack(pop)

struct ActivityOut
{
    bool recorded = false;
    std::string exec;                  // "codefetch" | "execute" | "none"
    std::vector<ActivityCell> cells;   // by object, then bucket
    std::vector<WriterRec>    writers;
    std::vector<FlowRec>      flows;   // by bucket, then from, then to
    std::vector<WxFinding>    wx;      // by first execution
    uint64_t writes = 0, execHits = 0, mismatches = 0, ranges = 0, bytesWatched = 0, ms = 0;
};

#pragma pack(push, 1)
struct ContentIdx     // 16 bytes
{
    uint64_t offset;  // into contents.bin
    uint32_t length;  // 0: no snapshot
    uint32_t unknown; // bytes the trace did not record (stored as 0)
};
static_assert(sizeof(ContentIdx) == 16);
#pragma pack(pop)

struct SnapshotOut
{
    bool recorded = false;
    uint32_t cap = 0;
    std::vector<ContentIdx> index;
    std::vector<uint8_t>    bytes;
    uint32_t mismatched = 0;           // blocks with kernel-written bytes still unread when the replay ended
    uint32_t readBack = 0;             // of those, read at their free
};

struct Model
{
    std::vector<Event>      events;
    std::vector<Position16> positions;
    std::vector<Block>      blocks;
    std::vector<Region>     regions;
    std::vector<Span>       spans;
    std::vector<HeapInfo>   heaps;
    std::vector<ThreadOut>  threads;
    std::vector<ModuleOut>  modules;
    std::vector<MarkerOut>  markers;
    SeriesOut               series;
    QualityOut              quality;
    CallsOut                calls;
    ActivityOut             activity;   // analyze stage "activity" (replay/activity.h)
    SnapshotOut             snapshots;  // analyze --snapshots on
    std::vector<std::string> warnings;
};

} // namespace ttds
