require 'mkmf'

extension_name = 'regfuzz'
dir_config(extension_name)

#$libs = append_library($libs,"regfuzz")
have_library('regfuzz', 'randomregex')

create_makefile(extension_name)

File.open("Makefile", "a") do |mf|
  mf.puts "regfuzz_wrap.c: ../../libregfuzz/regfuzz.i\n"
  mf.puts "\tswig -o $(PWD)/regfuzz_wrap.c -ruby ../../libregfuzz/regfuzz.i\n"
end
rm_f("regfuzz_wrap.c")
