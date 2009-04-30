

examples: static
	@-echo "A static libregfuzz has been dropped in this directory."
	@-echo "Type 'make' in your example subdirectory of choice to build more."

shared:
	$(MAKE) -C libregfuzz shared
	cp libregfuzz/lib/libregfuzz.so ./

static:
	$(MAKE) -C libregfuzz static
	cp libregfuzz/lib/libregfuzz.a ./


standalone:
	$(MAKE) -C libregfuzz standalone
	cp libregfuzz/regfuzz ./

all: examples shared static standalone

clean:
	@- rm *.so *.a regfuzz &> /dev/null
	$(MAKE) -C libregfuzz clean
