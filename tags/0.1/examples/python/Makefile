all: _regfuzz.so

regfuzz_wrap.c: ../../libregfuzz/regfuzz.i
	swig -python -o $(PWD)/$@ $^

.c.o:
	gcc -c $< -I/usr/include/python2.4

_regfuzz.so: regfuzz_wrap.o ../../libregfuzz.a
	ld -shared $^ -o $@

clean:
	@-rm *.o *.so regfuzz_wrap.c *.pyc regfuzz.py &> /dev/null
