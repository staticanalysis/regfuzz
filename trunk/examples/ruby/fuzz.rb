#!/usr/bin/ruby
# Copyright 2007-2009 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require 'cgi'
require 'regfuzz'

length_bias = 5
prog = 1024

Regfuzz.set_seed((rand*(2**32-1)).to_i)

if ARGV.length == 1
  Regfuzz.set_seed(ARGV[0].to_i);
elsif ARGV.length == 2
  Regfuzz.set_seed(ARGV[0].to_i);
  prog = ARGV[1].to_i
end

$stderr.close

bad = 0
matched = 0
unmatched = 0
0.upto(128000) do |count|
  r = Regfuzz.getregex(length_bias, (1<<1) | (1<<12))
  if (count % prog) == 0
    seed = Regfuzz.get_seed()
    print "count: #{count} seed: #{seed} bad: #{bad} matched: #{matched} unmatched: #{unmatched} sample: #{CGI.escape(r)}\n\n"
  end
  begin
    re = Regexp.new(r)
    m = re.match(r)
    if m
      matched += 1
    else
      unmatched += 1
    end
  rescue
    bad += 1
  end
end
