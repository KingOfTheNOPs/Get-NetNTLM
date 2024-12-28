all:
	x86_64-w64-mingw32-gcc -c Get-NetNTLM.c -o Get-NetNTLM.x64.o
	x86_64-w64-mingw32-strip --strip-unneeded Get-NetNTLM.x64.o 
	i686-w64-mingw32-gcc -c Get-NetNTLM.c -o Get-NetNTLM.x86.o
	
clean:
	rm Get-NetNTLM.x64.o
	rm Get-NetNTLM.x86.o
