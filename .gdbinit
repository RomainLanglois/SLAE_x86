set disassembly-flavor intel

define hook-stop
print/x $eax
print/x $ebx
print/x $ecx
print/x $edx
disassemble $eip,+10
end
