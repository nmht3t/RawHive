CC     := x86_64-w64-mingw32-gcc
CFLAGS := -O2 -masm=intel -Wall -std=c99 -mno-stack-arg-probe -fno-tree-loop-distribute-patterns -fno-builtin

rawhive: clean
	@mkdir -p dist
	$(CC) $(CFLAGS) -c rawhive.c -o dist/rawhive.x64.o
	@echo "[+] dist/rawhive.x64.o"

clean:
	rm -f dist/*.o
