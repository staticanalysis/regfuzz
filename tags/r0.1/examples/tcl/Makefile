all: regfuzz.so

regfuzz_wrap.c: ../../libregfuzz/regfuzz.i
	swig -tcl -o $(PWD)/$@ $^

.c.o:
	gcc -ggdb3 -c $< -I/usr/include/tcl8.3

regfuzz.so: regfuzz_wrap.o ../../libregfuzz.a
	ld -shared  $^ -o $@

clean:
	@- rm *.o regfuzz_wrap.c *.so &> /dev/null

