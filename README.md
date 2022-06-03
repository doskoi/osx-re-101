osx & ios re 101
==========

Work in progress as I am actively collecting these.

#### Must read

- https://reverse.put.as/
- https://blog.paloaltonetworks.com/tag/mac-os-x/
- https://www.synack.com/blog/r-d-projects/os-x-security-research/
- https://pewpewthespells.com/re.html
- https://github.com/bx/machO-tools
- https://github.com/kpwn/iOSRE

#### Keep these handy
- "OSX Mach-O File Format Reference" https://pewpewthespells.com/re/Mach-O_File_Format.pdf
- "OSX ABI" https://pewpewthespells.com/re/Mac_OS_X_ABI_Function_Calls.pdf
- Mach-O structures https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
- "OSX BSD system calls" https://sigsegv.pl/osx-bsd-syscalls/
- https://opensource.apple.com/source/xnu/xnu-2050.18.24/bsd/kern/syscalls.master

#### Basics

- "Universal Binary: The Mach-O file format" https://cocoaintheshell.whine.fr/2009/07/universal-binary-mach-o-format/
- "Basics of the Mach-O file format" https://samhuri.net/posts/2010/01/basics-of-the-mach-o-file-format/
- "How OS X Executes Applications" http://0xfe.blogspot.de/2006/03/how-os-x-executes-applications.html
- "Infecting Mach-O object format" https://papers.put.as/papers/macosx/2005/mach-o_infection.ppt
- "Under the iHood" https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-hotchkies.pdf
- "Dissection of minimal Intel 32-bits, 204 bytes, Mach-O "Hello World" executable file" http://seriot.ch/hello_macho.php
- "Crafting a Tiny Mach-O Executable" http://osxbook.com/blog/2009/03/15/crafting-a-tiny-mach-o-executable/
- "Parsing Mach-O files" http://lowlevelbits.org/parse-mach-o-files/
- "ELF vs. Mach-O" http://timetobleed.com/dynamic-linking-elf-vs-mach-o/
- "ELF vs. Mach-O 2" http://timetobleed.com/dynamic-symbol-table-duel-elf-vs-mach-o-round-2/
- "NASM Hello World for x86 and x86_64 Intel Mac OS X" https://gist.github.com/FiloSottile/7125822
- "Reverse Engineering the OS: A Practical Guide" https://www.youtube.com/watch?v=uQWH55yIgYU

#### Malware, Anti-debugging, infection techniques, obfuscation, and encryption

- "Infecting Mach-O" http://nicolascormier.com/documentation/security/Infecting_Mach-O_Files.pdf
- "Abusing the Mach-O format" http://cocoaintheshell.com/2009/10/abusing-mach-o
- "Multi-Platform Viruses Made Easy - A Case Study" http://vxer.org/lib/vjp00.html
- "Running executables on macOS from memory" https://blog.cylance.com/running-executables-on-macos-from-memory
- macos_execute_from_memory https://github.com/prsecurity/macos_execute_from_memory/blob/master/main.c
- "Understanding Apple's Binary Protection in Mac OS X" http://osxbook.com/book/bonus/chapter7/binaryprotection/
- "Macs get sick too" http://www.irongeek.com/i.php?page=videos/derbycon6/104-macs-get-sick-too-tyler-halfpop-jacob-soo
- "A Peek Under the Hood of iOS Malware" http://webdiis.unizar.es/~ricardo/files/papers/GR-WMA-16.pdf
- "Crafting macOS Rootkits" https://www.zdziarski.com/blog/wp-content/uploads/2017/02/Crafting-macOS-Root-Kits.pdf
- "Revisiting Mac OS X Kernel Rootkits" http://phrack.org/issues/69/7.html#article
- "Methods of malware persistence on Mac OS X" https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf
- "Let's Play: Practical OS X Malware Detection & Analysis" https://www.synack.com/wp-content/uploads/2016/03/RSA_OSX_Malware.pdf

#### Various research & tutorials

- "Reversing and Keygenning qwertyoruiop's Crackme" https://reverse.put.as/2018/10/06/reversing-and-keygenning-qwertyoruiop-crackme/
- "Cracking Tutorial #1 - "Sandwich" CrackMe" http://reverse.put.as/wp-content/uploads/2012/06/Sandwich_crackme_tut_qwertyoruiop.txt
- "Solving crackmes with LDPRELOAD" http://radare.today/solving-crackmes-with-ldpreload/
- "Analyzing Binaries with Hopper’s Decompiler" http://abad1dea.tumblr.com/post/23487860422/analyzing-binaries-with-hoppers-decompiler
- "Reverse Engineering Hopper Disassembler v3.9.9" https://www.youtube.com/watch?v=pCITcLqgS9Q
- "Reverse-Engineering iOS Apps: Hacking on Lyft" https://realm.io/news/conrad-kramer-reverse-engineering-ios-apps-lyft/
- "Jailbreak iOS 8.1.2 and Analyze Related Exploits" http://proteaswang.blogspot.com/2017/04/jailbreak-ios-812-and-analyze-related.html
-  "Attacking The XNU Kernel in El Capitan" https://www.blackhat.com/docs/eu-15/materials/eu-15-Todesco-Attacking-The-XNU-Kernal-In-El-Capitain.pdf
- "Shooting the OSX El Capitan Kernel Like a Sniper" https://speakerdeck.com/flankerhqd/shooting-the-osx-el-capitan-kernel-like-a-sniper
- "The Italian morons are back! What are they up to this time?" https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/
- "The Journey of a complete OSX privilege escalation with a single vulnerability - Part 1" http://keenlab.tencent.com/en/2016/07/29/The-Journey-of-a-complete-OSX-privilege-escalation-with-a-single-vulnerability-Part-1/
- "iOS 10 Kernel Heap Revisted" http://gsec.hitb.org/materials/sg2016/D2%20-%20Stefan%20Esser%20-%20iOS%2010%20Kernel%20Heap%20Revisited.pdf
- "Who needs decrypted kernels anyways?" http://blog.offcellresearch.com/security/apple/ios/kernel/2016/08/23/who-needs-decrypted-kernels-anyways.html
- "Mac OS X Privilege Escalation via Use-After-Free: CVE-2016-1828" https://bazad.github.io/2016/05/mac-os-x-use-after-free/
- "PEGASUS iOS Kernel Vulnerability Explained" http://sektioneins.de/en/blog/16-09-02-pegasus-ios-kernel-vulnerability-explained.html
- "Behind the Scenes with iOS Security" https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf
- "The Apple Sandbox: Deeper Into The Quagmire" https://www.youtube.com/watch?v=mG715HcDgO8
- “A deep-dive into the many flavors of IPC available on OS X.” https://vimeo.com/127859750
- "Analysis of iOS 9.3.3 Jailbreak & Security Enhancements of iOS 10" http://powerofcommunity.net/poc2016/pangu.pdf
- "Fried Apples: Jailbreak DIY" https://speakerdeck.com/mbazaliy/fried-apples-jailbreak-diy
- "Reversing a macOS Kernel Extension" (DSMOS) http://lightbulbone.com/2016/10/04/intro-to-macos-kernel-debugging.html
- "Demystifying the Secure Enclave Processor" http://mista.nu/research/sep-paper.pdf
- "Leveraging Apple's Game Engine to Detect macOS Threats" https://objectivebythesea.com/v1/talks/OBTS_v1_Malm_Stein.pdf
- "Get Cozy with OpenBSM Auditing" https://objective-see.com/talks/Wardle_ShmooCon2018.pdf
- "Real-time auditing on macOS with OpenBSM" https://meliot.me/2017/07/02/mac-os-real-time-auditing/

#### Kernel extension (KEXT) development

- "KEXT Controls and Notifications" https://developer.apple.com/library/content/documentation/Darwin/Conceptual/NKEConceptual/control/control.html
- "Network Kernel Extensions Reference" https://developer.apple.com/library/content/documentation/Darwin/Conceptual/NKEConceptual/reference/reference.html#//apple_ref/doc/uid/TP40001858-CH232-BBAGGGED
- "Working with TrustedBSD in Mac OS X" https://sysdev.me/trusted-bsd-in-osx/
- "BUILDING AN APPLE OSX KERNEL MODULE WITH CMAKE – C/C" http://www.goodbits.ca/index.php/2017/09/25/building-an-apple-osx-kernel-module-with-cmake-cc/
- "Debugging macOS Kernel using VirtualBox" https://klue.github.io/blog/2017/04/macos_kernel_debugging_vbox/
- "Remote Kext Debugging" https://rednaga.io/2017/04/09/remote_kext_debugging/
- "Introduction to macOS Kernel Debugging" https://lightbulbone.com/posts/2016/10/intro-to-macos-kernel-debugging/
- "Kernel debugging with LLDB and VMWare Fusion" http://ddeville.me/2015/08/kernel-debugging-with-lldb-and-vmware-fusion
- "Monitoring Process Creation via the Kernel (Part I)" https://objective-see.com/blog.html#blogEntry9
- "Monitoring Process Creation via the Kernel (Part II)" https://objective-see.com/blog/blog_0x0A.html
- "Monitoring Process Creation via the Kernel (Part III)" https://objective-see.com/blog/blog_0x0B.html
- "Monitoring macOS, Part I: Monitoring Process Execution via MACF" https://www.fortinet.com/blog/threat-research/monitoring-macos--part-i--monitoring-process-execution-via-macf.html
- "Monitoring macOS, Part II: Monitoring File System Events and Dylib Loading via MACF" https://www.fortinet.com/blog/threat-research/monitor-file-system-events-and-dylib-loading-via-macf-on-macos.html
- "Monitoring macOS, Part III: Monitoring Network Activities Using Socket Filters" https://www.fortinet.com/blog/threat-research/monitoring-macos--part-iii--monitoring-network-activities-using-.html
- "A binary whitelisting/blacklisting system for Mac OS X" https://github.com/google/santa

#### Other
- "The Python bites your apple - fuzzing and exploiting OSX Kernel bugs" https://speakerdeck.com/flankerhqd/the-python-bites-your-apple-fuzzing-and-exploiting-osx-kernel-bugs
- "Artefacts and tricks for Mac OS X" http://sud0man.blogspot.fr/2015/05/artefacts-for-mac-os-x.html?m=1
- "Collection of forensics artifacs location for Mac OS X and iOS" https://github.com/pstirparo/mac4n6
- "New macOS Sierra (10.12) Forensic Artifacts – Introducing Unified Logging" https://www.mac4n6.com/blog/2016/11/13/new-macos-sierra-1012-forensic-artifacts-introducing-unified-logging
- "A curated list of shell commands and tools specific to OS X" https://github.com/herrbischoff/awesome-osx-command-line
- "OS X Security and Privacy Guide" https://github.com/drduh/OS-X-Security-and-Privacy-Guide
- "A launchd tutorial" http://launchd.info/
- https://objective-see.com/index.html
- "OS X malloc introspection tool" https://github.com/blankwall/MacHeap
- "MacOS Hardening Guide" http://newosxbook.com/files/moxii3/AppendixA.pdf by Jonathan Levin
- "Checkout4Mac" http://sud0man.blogspot.sk/2016/10/new-version-of-checkout4mac-02.html
- "OSX kernel fuzzer" https://github.com/SilverMoonSecurity/PassiveFuzzFrameworkOSX
- "iOS instrumentation without jailbreak" https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/
- "MacOS monitoring the open source way" https://blogs.dropbox.com/tech/2018/04/4696/
- "Mac OS X El Capitan (10.11) and task_for_pid()" https://attilathedud.me/mac-os-x-el-capitan-10-11-and-task_for_pid/

#### Crackmes and challenges

- https://reverse.put.as/crackmes/
- "Exercises" section in http://beginners.re/Reverse_Engineering_for_Beginners-en.pdf

#### Books

- "The Mac Hacker's Handbook" by Charlie Miller, Dino Dai Zovi
- "Mac OS X and iOS Internals: To the Apple's Core" by Jonathan Levin
- "Mac OS X Internals: A Systems Approach" by Amit Singh
- "iOS App Reverse Engineering" https://github.com/iosre/iOSAppReverseEngineering
- "iOS Hacker's Handbook" by Charlie Miller, Dion Blazakis, Dino Dai Zovi, Stefan Esser, Vincenzo Iozzo, Ralf-Philip Weinmann 
- "Hacking and Securing iOS Applications" by Jonathan Zdziarski

---

**Reverse Engineering Resources**

**Debugging**

These are very important guides for understanding the debugging process and how applications work.

- Mac OS X Debugging Magic Technical Note (TN2124) ([link](https://developer.apple.com/library/mac/technotes/tn2124/_index.html) - [PDF Mirror](https://pewpewthespells.com/re/Technical_Note_TN2124.pdf))
- iOS Debugging Magic Technical Note (TN2239) ([link](https://developer.apple.com/library/ios/technotes/tn2239/_index.html) - [PDF Mirror](https://pewpewthespells.com/re/Technical_Note_TN2239.pdf))
- Understanding and Analyzing iOS Application Crash Reports (TN2151) ([link](https://developer.apple.com/library/ios/technotes/tn2151/_index.html) - [PDF Mirror](https://pewpewthespells.com/blog/re/Understanding_and_Analyzing_iOS_Application_Crash_Reports.pdf))
- Malloc Debug Environment Variables ([link](https://developer.apple.com/library/mac/releasenotes/DeveloperTools/RN-MallocOptions/) - [PDF Mirror](https://pewpewthespells.com/re/Malloc_Debug_En_Vars.pdf))

**Mach-O Binaries**

Mac OS X and iOS use Mach-O file format for executable binaries and shared libraries. It supports multiple architectures in one binary file (Universal or fat binaries).

- Mach-O Wikipedia ([link](http://en.wikipedia.org/wiki/Mach-O))
- OS X ABI Mach-O File Format Reference ([link](https://developer.apple.com/library/mac/documentation/developertools/Conceptual/MachORuntime/Reference/reference.html) - [PDF](https://developer.apple.com/library/mac/documentation/developertools/Conceptual/MachORuntime/Mach-O_File_Format.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Mach-O_File_Format.pdf))
- Mach-O Programming Topics ([link](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html) - [PDF](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachOTopics/Mach-O_Programming.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Mach-O_Programming.pdf))

**Analysis**

Guides and introductory material to binary analysis.

- Analyzing Binaries with Hopper ([link](http://abad1dea.tumblr.com/post/23487860422/analyzing-binaries-with-hoppers-decompiler))

**System ABIs**

Calling conventions define how functions and subroutines receive the parameters passed to them from the calling function.

- ABI Wikipedia ([link](http://en.wikipedia.org/wiki/Application_binary_interface))
- Calling Conventions Wikipedia ([link](http://en.wikipedia.org/wiki/Calling_convention))
- Mac OS X ABI ([link](https://developer.apple.com/library/mac/documentation/developertools/conceptual/LowLevelABI/000-Introduction/introduction.html) - [PDF](https://developer.apple.com/library/mac/documentation/developertools/conceptual/LowLevelABI/Mac_OS_X_ABI_Function_Calls.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Mac_OS_X_ABI_Function_Calls.pdf))
- iOS ABI ([link](https://developer.apple.com/library/ios/documentation/Xcode/Conceptual/iPhoneOSABIReference/Introduction/Introduction.html) - [PDF](https://developer.apple.com/library/ios/documentation/Xcode/Conceptual/iPhoneOSABIReference/iPhoneOSABIReference.pdf) - [PDF Mirror](https://pewpewthespells.com/re/iPhoneOSABIReference.pdf))
- Dynamic Library Programming Topics ([link](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/DynamicLibraries/000-Introduction/Introduction.html) - [PDF](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/DynamicLibraries/Dynamic_Libraries.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Dynamic_Libraries.pdf)) ([Companion File](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/DynamicLibraries/DynamicLibraries_companion.zip) - [Companion File Mirror](https://pewpewthespells.com/re/DynamicLibraries_companion.zip))
- OS X ABI Dynamic Loader Reference ([link](https://developer.apple.com/library/mac/documentation/developertools/Reference/MachOReference/Reference/reference.html) - [PDF](https://developer.apple.com/library/mac/documentation/developertools/Reference/MachOReference/MachOReference.pdf) - [PDF Mirror](https://pewpewthespells.com/re/MachOReference.pdf))

**Language Resources**

Language specific knowledge is often required to understand what is going on behind the scenes.

- Intel x86 Architecture ([PDF](http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-manual-325462.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Intel_x86_64_Ref.pdf))
- Introduction to x64 Assembly ([PDF](http://software.intel.com/sites/default/files/m/d/4/1/d/8/Introduction_to_x64_Assembly.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Introduction_to_x64_Assembly.pdf))
- ARM Architecture for ARMv7 ([PDF Mirror](https://pewpewthespells.com/re/arm_architecture_reference_manual.pdf))
- ARM Architecture for ARM64 ([PDF Mirror](https://pewpewthespells.com/re/arm64_architecture_reference_manual.pdf))
- OS X Assembler Reference ([link](https://developer.apple.com/library/mac/documentation/DeveloperTools/Reference/Assembler/000-Introduction/introduction.html) - [PDF](https://developer.apple.com/library/mac/documentation/DeveloperTools/Reference/Assembler/Assembler.pdf) - [PDF Mirror](https://pewpewthespells.com/re/Assembler.pdf))
- Learn C The Hard Way ([link](http://c.learncodethehardway.org/book/))
- The C Library Reference Guide ([link](http://www.acm.uiuc.edu/webmonkeys/book/c_guide/))
- Objective-C Language ([link](https://developer.apple.com/library/mac/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/Introduction/Introduction.html) - [PDF](https://developer.apple.com/library/mac/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ProgrammingWithObjectiveC.pdf) - [PDF Mirror](https://pewpewthespells.com/re/ProgrammingWithObjectiveC.pdf))
- Objective-C Runtime ([link](https://developer.apple.com/library/mac/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Introduction/Introduction.html) - [PDF](https://developer.apple.com/library/mac/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/ObjCRuntimeGuide.pdf) - [PDF Mirror](https://pewpewthespells.com/re/ObjCRuntimeGuide.pdf))

**Further Reading**

Collection of blogs and reading resources that give deep insight into how many aspects of languages and system functionality.

- NSBlog ([link](http://www.mikeash.com/pyblog/))
- Reverse Engineering Mac OS X ([link](http://reverse.put.as/))
- Landon's Blog ([link](http://landonf.bikemonkey.org/))
- OS X Internals ([link](http://osxbook.com/))
- Greg Parker's Blog ([link](http://www.sealiesoftware.com/blog/))
- Ridiculous Fish ([link](http://ridiculousfish.com/blog/))
- Snare's Blog ([link](http://ho.ax/))
- To The Apple's Core ([link](http://www.newosxbook.com/index.php))
- The Objective-C Runtime: Understanding and Abusing ([link](http://www.phrack.org/issues.html?issue=66&id=4))

**Tools**

**Mach-O Binary Analyzers:**

- MachOViewer ([Homepage](http://sourceforge.net/projects/machoview/))

**Hex Editors:**

- Hex Fiend ([Homepage](http://ridiculousfish.com/hexfiend/))
- 0xED ([Homepage](http://www.suavetech.com/0xed/))
- Synalyze It! ([Homepage](http://www.synalysis.net/))

**Disassemblers:**

- Hopper ([Homepage](http://www.hopperapp.com/))
- IDA ([Homepage](https://www.hex-rays.com/products/ida/index.shtml))
- otool ([man page](x-man-page://1/otool))
- otx ([Homepage](http://otx.osxninja.com/))

**Decompilers:**

- Hopper ([Homepage](http://www.hopperapp.com/))
- Hex-Rays ([Homepage](https://www.hex-rays.com/products/decompiler/index.shtml))
- classdump ([Homepage](http://stevenygard.com/projects/class-dump/))
- codedump (i386) ([Source ZIP](https://pewpewthespells.com/re/i386codedump.zip))

**Debuggers:**

- GDB (Not shipped on OS X anymore) ([Homepage](http://www.sourceware.org/gdb/))
- LLDB ([Homepage](http://lldb.llvm.org/) - [man page](x-man-page://1/lldb))
- PonyDebugger ([link](https://github.com/square/PonyDebugger))

**Memory Editors:**

- Bit Slicer ([Homepage](http://zorg.tejat.net/programs/) - [Source](https://bitbucket.org/zorgiepoo/bit-slicer/))

**Various Command Line Tools:**

- nm ([man page](x-man-page://1/nm))
- strings ([man page](x-man-page://1/strings))
- dsymutil ([man page](x-man-page://1/dsymutil))
- install\_name\_tool ([man page](x-man-page://1/install_name_tool))
- ld ([man page](x-man-page://1/ld))
- lipo ([man page](x-man-page://1/lipo))
- codesign ([man page](x-man-page://1/codesign))
- hexdump ([man page](x-man-page://1/hexdump))
- dyld\_shared\_cache ([link](x-man-page://1/hexdump))
- vbindiff ([link](http://www.cjmweb.net/vbindiff/))
- binwalk ([link](https://code.google.com/p/binwalk/))
- xpwntool ([link](http://theiphonewiki.com/wiki/Xpwntool))
- objdump ([link](https://sourceware.org/binutils/docs/binutils/objdump.html))

**Useful Source Repositories:**

- Apple Source Code ([link](https://www.opensource.apple.com/))
- PLCrashReporter ([link](https://www.plcrashreporter.org/contribute))
- Mike Ash's Github ([link](https://github.com/mikeash))
- Landon Fuller's Github ([link](https://github.com/landonf))
- Jonathan Rentzsch's Github ([link](https://github.com/rentzsch))
- fG!'s Github ([link](https://github.com/gdbinit))
