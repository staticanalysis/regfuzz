
fuzzer.so:
	gcc -I/usr/include/postgresql -fpic -shared -o fuzzer.so fuzzer.c

clean:
	rm fuzzer.so &> /dev/null
