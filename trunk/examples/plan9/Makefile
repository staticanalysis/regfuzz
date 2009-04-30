all: plan9fzr plan9tst

plan9fzr:
	gcc plan9fzr.c -L. -lregexp9 -lutf -lfmt -I. -o plan9fzr

plan9tst:
	gcc plan9tst.c -L. -lregexp9 -lutf -lfmt -I. -o plan9tst

clean:
	rm plan9tst plan9fzr
