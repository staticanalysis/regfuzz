all: RegexFuzzHarness.exe RegexTest.exe

RegexFuzzHarness.exe: RegexFuzzHarness.mcs RegexGenerator.mcs
	mcs $^

RegexTest.exe: RegexTest.mcs RegexGenerator.mcs
	mcs $^

clean:
	@- rm *.exe
