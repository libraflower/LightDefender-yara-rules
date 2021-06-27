rule Ransom_uz {
   meta:
      description = "Ransom.uz"
      author = "LightDefender"
      date = "2021-06-27"
      hash1 = "177d6fc932b61cea08b4f243548bfc6288c8485af48b13f9270e790691209542"
      hash2 = "51fb2e1003298cf34cbefc408888c4e1b6bae6ce344486242b959857e89a2753"
   strings:
      $x1 = ".lib section in a.out corrupted/Desktop/README_TO_RECOVER.html11368683772161602973937988281255684341886080801486968994140625Cent" ascii
      $x2 = "asn1: Unmarshal recipient value is nil math/big: buffer too small to fit valuemismatched count during itab table copymspan.sweep" ascii
      $x3 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii
      $x5 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii
      $x6 = "11579208921035624876269744694940757352999695522413576034242225906106851204436911579208921035624876269744694940757353008614341529" ascii
      $x7 = "workbuf is empty initialHeapLive= spinningthreads=%%!%c(big.Int=%s), p.searchAddr = 0123456789ABCDEFX0123456789abcdefx0601021504" ascii
      $x8 = "x509: cannot verify signature: algorithm unimplementedSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonescasfrom_Gscanst" ascii
      $x9 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125Central America Standard TimeCentral Pacific Standard " ascii
      $x10 = "Variation_Selector\\\\.\\PHYSICALDRIVE0bad manualFreeListconnection refusedfaketimeState.lockfile name too longforEachP: not don" ascii
      $x11 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedaddress not a sta" ascii
      $x12 = "152587890625762939453125Bidi_ControlFindNextFileGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii
      $x13 = "StatusEx returned invalid mode= runtime: netpoll: PostQueuedCompletionStatus failed (errno= /c C:\\Windows\\System32\\vssadmin.e" ascii
      $x14 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeSao Tome Standard TimeTasmania Standard " ascii
      $x15 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid baseinvalid slotiphlpapi.dllkernel32.dllmadvdontneedmheapSpe" ascii
      $x16 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
      $x17 = "structure needs cleaning bytes failed with errno= to unused region of span2910383045673370361328125AUS Central Standard TimeAUS " ascii
      $x18 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedaddress not a sta" ascii
      $x19 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii
      $x20 = "bad flushGen bad map statedalTLDpSugct?empty integerexchange fullfatal error: gethostbynamegetservbynameinvalid base kernel32.dl" ascii
      $x21 = "C:\\Program FilesCreateDirectoryWDnsNameCompare_WDuplicateTokenExFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value " ascii
      $s22 = "c format errorfractional secondg already scannedglobalAlloc.mutexinteger too largeinvalid bit size locked m0 woke upmark - bad s" ascii
      $s23 = "-struct typeruntime: VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime:" ascii
      $s24 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $s25 = " lockedg= lockedm= m->curg= marked   method:  ms cpu,  not in [ runtime= s.limit= s.state= threads= u_a/u_g= unmarked wbuf1.n= w" ascii
      $s26 = "rbage collectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availablenon-" ascii
      $s27 = "r32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  m->gs" ascii
      $s28 = "ementById(\"idarea\");button.addEventListener(\"click\", function(event) {event.preventDefault();input.select();document.execCom" ascii
      $s29 = "1907348632812595367431640625: extra text: CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC" ascii
      $s30 = "mstartbad sequence numberbad value for fielddevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile alr" ascii
      $s31 = "eHandleFailed to find Failed to load FlushViewOfFileGetAdaptersInfoGetCommandLineWGetProcessTimesGetStartupInfoWHanifi_RohingyaI" ascii
      $s32 = "Timeaddress already in useadvapi32.dll not foundargument list too longassembly checks failedbad g->status in readybad sweepgen i" ascii
      $s33 = "ueOld_PersianOld_SogdianOpenProcessPau_Cin_HauRegCloseKeySHA-512/224SHA-512/256SetFileTimeShell32.dllSignWritingSoft_DottedVirtu" ascii
      $s34 = "Saint Pierre Standard TimeSetFileInformationByHandleSouth Africa Standard TimeW. Australia Standard TimeWest Pacific Standard Ti" ascii
      $s35 = "iewOfFileMasaram_GondiMende_KikakuiOld_HungarianRegDeleteKeyWRegEnumKeyExWRegEnumValueWRegOpenKeyExWShellExecuteWVirtualUnlockWr" ascii
      $s36 = "GetComputerNameWGetCurrentThreadGetFullPathNameWGetLongPathNameWImperial_AramaicMeroitic_CursiveNetApiBufferFreeOpenProcessToken" ascii
      $s37 = "itCodeProcessGetFileAttributesWGetModuleFileNameWIran Standard TimeLookupAccountNameWOmsk Standard TimeRCodeServerFailureRFS spe" ascii
      $s38 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii
      $s39 = "d open-coded defers in deferreturnunknown runnable goroutine during bootstrap using value obtained using unexported fieldcompile" ascii
      $s40 = "wrong medium type  but memory size  because dotdotdot to non-Go memory , locked to thread298023223876953125: day out of rangeAra" ascii
      $s41 = "cialmspanSpecialnetapi32.dllno such hostnot pollableraceFiniLockreflect.Copyreleasep: m=runtime: gp=runtime: sp=self-preemptshor" ascii
      $s42 = ",M3.2.0,M11.1.00601021504Z0700476837158203125: cannot parse <invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicat" ascii
      $s43 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
      $s44 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenici" ascii
      $s45 = "eback did not unwind completelytransport endpoint is not connectedx509: decryption password incorrectx509: wrong Ed25519 public " ascii
      $s46 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii
      $s47 = "iteConsoleWadvapi32.dll" fullword ascii
      $s48 = "attempt to execute system stack code on user stackcompileCallback: function argument frame too largemallocgc called with gcphase" ascii
      $s49 = "ryptReleaseContextEgypt Standard TimeGC work not flushedGetCurrentProcessIdGetSystemDirectoryWGetTokenInformationHaiti Standard " ascii
      $s50 = "level 3 resetload64 failedmin too largenil stackbaseout of memoryparsing time powrprof.dll" fullword ascii
      $s51 = "B Standard TimeGetCurrentProcessGetShortPathNameWLookupAccountSidWOld_North_ArabianOld_South_ArabianOther_ID_ContinueRegLoadMUIS" ascii
      $s52 = "runtime.getempty.func1" fullword ascii
      $s53 = "runtime.getempty" fullword ascii
      $s54 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii
      $s55 = "adByte: at beginning of stringstrings.Reader.WriteTo: invalid WriteString countx509: Ed25519 key encoded with illegal parameters" ascii
      $s56 = "panic holding lockspanicwrap: no ( in panicwrap: no ) in reflect.Value.Fieldreflect.Value.Floatreflect.Value.Indexreflect.Value." ascii
      $s57 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii
      $s58 = "bad flushGen bad map statedalTLDpSugct?empty integerexchange fullfatal error: gethostbynamegetservbynameinvalid base kernel32.dl" ascii
      $s59 = "TimeIDS_Binary_OperatorIndia Standard TimeKey type is not RSAKhitan_Small_ScriptKorea Standard TimeLibya Standard TimeMultiByteT" ascii
      $s60 = "runtime.execute" fullword ascii
      $s61 = "amegetsocknamei/o timeoutmSpanManualmethodargs(mswsock.dllnetpollInitreflect.SetreflectOffsruntime: P runtime: p scheddetailsecu" ascii
      $s62 = "an.sweep: state=notesleep not on g0ntdll.dll not foundnwait > work.nprocspanic during mallocpanic during panic" fullword ascii
      $s63 = "ot Gdead)integer not minimally-encodedinvalid length of trace eventio: read/write on closed pipemachine is not on the networkno " ascii
      $s64 = "meCentral Standard TimeEastern Standard TimeGetProfilesDirectoryWInscriptional_PahlaviLookupPrivilegeValueWMagadan Standard Time" ascii
      $s65 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii
      $s66 = "sync.runtime_SemacquireMutex" fullword ascii
      $s67 = "os.Executable" fullword ascii
      $s68 = "runtime.dumpgstatus" fullword ascii
      $s69 = "runtime.injectglist" fullword ascii
      $s70 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii
      $s71 = "runtime.tracebackHexdump" fullword ascii
      $s72 = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"><meta na" ascii
      $s73 = "runtime.tracebackHexdump.func1" fullword ascii
      $s74 = "ves_AkuruExitProcessFreeLibraryGOTRACEBACKGetFileTypeIdeographicMedefaidrinMoveFileExWNandinagariNetShareAddNetShareDelNew_Tai_L" ascii
      $s75 = "runtime.hexdumpWords.func1" fullword ascii
      $s76 = "ash state identifiergcSweep being done but phase is not GCoffmheap.freeSpanLocked - invalid span statemheap.freeSpanLocked - inv" ascii
      $s77 = ":#999; color: darkred;\">UZ Ransomware</h4></center><script>var button = document.getElementById(\"copyID\"),input = document.ge" ascii
      $s78 = "runtime.dumpregs" fullword ascii
      $s79 = "uireContextWEgyptian_HieroglyphsGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetProcessMemory" ascii
      $s80 = "cas64 failedchan receivedumping heapend tracegc" fullword ascii
      $s81 = "runtime.gcDumpObject" fullword ascii
      $s82 = "runtime.injectglist.func1" fullword ascii
      $s83 = "runtime.hexdumpWords" fullword ascii
      $s84 = "anRIPEMD-160SaurashtraWSACleanupWSASocketWWSAStartupatomicand8complex128debug calldnsapi.dllexitThreadfloat32nanfloat64nangetsoc" ascii
      $s85 = "syscall.GetCurrentProcess" fullword ascii
      $s86 = "ot emptywrite of Go pointer ws2_32.dll not found of unexported method previous allocCount=, levelBits[level] = 18626451492309570" ascii
      $s87 = "wprocessorrevision" fullword ascii
      $s88 = "os.(*fileStat).Sys" fullword ascii
      $s89 = "m.dll not foundzero length segment markroot jobs done" fullword ascii
      $s90 = ", i = , not 390625<-chanAnswerArabicAugustBrahmiCarianChakmaCommonCopticFormatFridayGOROOTGetACPGothicHangulHatranHebrewHyphenKa" ascii
      $s91 = "vide by zerointerface conversion: internal inconsistencyinvalid number base %dkernel32.dll not foundminpc or maxpc invalidnetwor" ascii
      $s92 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)invalid booleaninvalid pointerkey has expiredmalloc deadlockmisaligned " ascii
      $s93 = "dwprocessortype" fullword ascii
      $s94 = "wprocessorlevel" fullword ascii
      $s95 = "mote address changedruntime.main not on m0runtime: work.nwait = runtime:scanstack: gp=s.freeindex > s.nelemsscanstack - bad stat" ascii
      $s96 = "dwactiveprocessormask" fullword ascii
      $s97 = "dwnumberofprocessors" fullword ascii
      $s98 = "OpenThreadTokenOther_LowercaseOther_UppercaseProcess32FirstWPsalter_PahlaviRegCreateKeyExWRegDeleteValueWUnmapViewOfFile]" fullword ascii
      $s99 = "152587890625762939453125Bidi_ControlFindNextFileGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii
      $s100 = " worker initGetConsoleModeGetProcAddressGetUserNameExWMB; allocated NetUserGetInfoOAEP EncryptedOther_ID_StartPattern_SyntaxProc" ascii
      $s101 = "*runtime.rwmutex" fullword ascii
      $s102 = "runtime.(*rwmutex).runlock" fullword ascii
      $s103 = "pc=%!(NOVERB)%!Weekday((BADINDEX), bound = , limit = /dev/stdin12207031256103515625: parsing AdditionalBad varintC:\\WindowsCanc" ascii
      $s104 = "Other_AlphabeticRCodeFormatErrorRegQueryInfoKeyWRegQueryValueExWRemoveDirectoryWSetFilePointerExTerminateProcessZanabazar_Square" ascii
      $s105 = "?*struct { lock runtime.mutex; used uint32; fn func(bool) bool }" fullword ascii
      $s106 = "targetpc" fullword ascii
      $s107 = "wrunlock of unlocked rwmutexruntime: asyncPreemptStack=runtime: checkdead: find g runtime: checkdead: nmidle=runtime: corrupted " ascii
      $s108 = "Int63ninvalid request descriptorname not unique on networkno CSI structure availableno message of desired typenotewakeup - doubl" ascii
      $s109 = "runtime.getlasterror" fullword ascii
      $s110 = "roc1: new g is not Gdeadnewproc1: newg missing stackos: process already finishedprotocol driver not attachedreflect.MakeSlice: l" ascii
      $s111 = "x error scanning booleantimeBegin/EndPeriod not foundtoo many open files in systemzero length OBJECT IDENTIFIER (types from diff" ascii
      $s112 = "runtime.(*rwmutex).rlock.func1" fullword ascii
      $s113 = "e: GetQueuedCompletionStatusEx failed (errno= runtime: use of FixAlloc_Alloc before FixAlloc_Init" fullword ascii
      $s114 = "internal/testlog.Logger" fullword ascii
      $s115 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii
      $s116 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii
      $s117 = "*runtime.mutex" fullword ascii
      $s118 = " zombie, goid=, j0 = .tar.gz19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625AvestanBengaliBrailleChanDirCopySidCypriotDe" ascii
      $s119 = "runtime.(*rwmutex).rlock" fullword ascii
      $s120 = "23283064365386962890625<invalid reflect.Value>Argentina Standard TimeAstrakhan Standard TimeCertGetCertificateChainDestroyEnviro" ascii
      $s121 = "t) - deadlock!reflect.FuncOf does not support more than 50 argumentsruntime: signal received on thread not created by Go." fullword ascii
      $s122 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
      $s123 = "runtime.envKeyEqual" fullword ascii
      $s124 = "lobberfreeclosesocketcreated by crypt32.dllfile existsfloat32nan2float64nan1float64nan2float64nan3gccheckmarkgeneralizedgetpeern" ascii
      $s125 = "syscall.OpenCurrentProcessToken" fullword ascii
      $s126 = "runtime.templateThread" fullword ascii
      $s127 = "ast.</p><hr><h3>How to Pay</h3><p>Send email to us. Our mail address is TimaiosShraga12@protonmail.com</p><p>*If you want to rec" ascii
      $s128 = "syscall.OpenProcessToken" fullword ascii
      $s129 = "runtime.startTemplateThread" fullword ascii
      $s130 = " zombie, goid=, j0 = .tar.gz19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625AvestanBengaliBrailleChanDirCopySidCypriotDe" ascii
      $s131 = "runtime.putempty" fullword ascii
      $s132 = "08UTC-09UTC-11WanchoYezidi[]bytechan<-domainefencegopherheaderlistenminuteobjectpopcntremovesecondselectsocketstringstructsweep " ascii
      $s133 = "netpoll: PostQueuedCompletionStatus failedcasfrom_Gscanstatus: gp->status is not in scan statecrypto/rsa: message too long for R" ascii
      $s134 = "ize (2220446049250313080847263336181640625_cgo_notify_runtime_init_done missingall goroutines are asleep - deadlock!cannot exec " ascii
      $s135 = "XENIX semaphores availablenotesleep - waitm out of syncnumerical result out of rangeoperation already in progresspadding contain" ascii
      $s136 = "pected runtime.netpoll error: x509: unknown public key algorithm'_' must separate successive digits17763568394002504646778106689" ascii
      $s137 = "internal/poll.execIO" fullword ascii
      $s138 = "os.executable" fullword ascii
      $s139 = "unlock: lock countsigsend: inconsistent statestack size not a power of 2startm: negative nmspinningstopTheWorld: holding locksti" ascii
      $s140 = ": m has pstartm: m is spinningstate not recoverabletimer data corruption%SystemRoot%\\system32\\/lib/time/zoneinfo.zip4656612873" ascii
      $s141 = "runqhead" fullword ascii
      $s142 = "math.Log2" fullword ascii
      $s143 = "os.commandLineToArgv" fullword ascii
      $s144 = "runtime.errorAddressString.Error" fullword ascii
      $s145 = "*syscall.DLL" fullword ascii
      $s146 = " memoryruntime: failed to commit pagesruntime: split stack overflow: slice bounds out of range [%x:]slice bounds out of range [:" ascii
      $s147 = "runtime.bgsweep" fullword ascii
      $s148 = "sync.(*Mutex).lockSlow" fullword ascii
      $s149 = "1907348632812595367431640625: extra text: CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC" ascii
      $s150 = "reflect.StructTag.Get" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
