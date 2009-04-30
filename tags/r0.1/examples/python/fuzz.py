#!/usr/bin/python
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


import regfuzz,_sre,re,sys,urllib

lenbias = 8
progress = 2048

regfuzz.set_seed(int(sys.argv[1]))

match = 0
bad = 0

for i in range(int(sys.argv[2])):
    regex = regfuzz.getregex(lenbias, (1<<3))
    # print urllib.quote(regex)
    if i % progress == 0:
        # print "sample: " + urllib.quote(regex)
        print "count: " + str(i) + " match: " + str(match) + " bad: " + str(bad)
    try:
        # try sre first
        _sre.compile(regex, ~0, [])
        # these may throw
        r = re.compile(regex)
        if re.search(r,regex):
            match += 1;
    except:
        bad += 1
        continue
