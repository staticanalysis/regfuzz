all: regfuzz

regfuzz_wrap.c: ../../libregfuzz.a
	swig -ocaml -o $(PWD)/regfuzz_wrap.c ../../libregfuzz/regfuzz.i
	swig -ocaml -co swig.mli
	swig -ocaml -co swig.ml

regfuzz: regfuzz_wrap.c
	ocamlc -c swig.mli
	ocamlc -c swig.ml
	ocamlc -c regfuzz_wrap.c ../../libregfuzz/regfuzz.c
	ocamlc -c regfuzz.mli
	ocamlc -c regfuzz.ml
	ocamlmktop -custom swig.cmo  regfuzz_wrap.o regfuzz.cmo regfuzz.o -o regfuzz

clean:
	@-rm *.cmo *.cmi *.o swig.* regfuzz regfuzz_wrap.c  regfuzz.ml regfuzz.mli &>/dev/null
