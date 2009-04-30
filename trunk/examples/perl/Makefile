all: regfuzz.so

regfuzz_wrap.c: ../../libregfuzz/regfuzz.i
	swig -perl -o $(PWD)/$@ $^

.c.o:
	gcc -ggdb3  -c $< `perl -MExtUtils::Embed -e ccopts`


regfuzz.so: regfuzz_wrap.o ../../libregfuzz.a
	ld -G $^ -o $@

clean:
	rm regfuzz_wrap* *.o *.so regfuzz.pm &> /dev/null
