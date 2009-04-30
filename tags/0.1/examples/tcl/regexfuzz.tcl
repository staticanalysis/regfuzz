#!/usr/bin/tclsh
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

load regfuzz.so regfuzz

set seed [lrange $argv 0 0]
set progress 1024
set good 0
set bad 0
set count 0

set_seed $seed
puts [get_seed]
puts [format "count: %d, good: %d, bad: %d, seed: %d" $count $good $bad [get_seed]]

while {1} {
    set re [getregex 8 0x20]
    set count [expr $count + 1]
    if ![expr $count % $progress] { 
        puts [format "count: %d, good: %d, bad: %d, seed: %d" $count $good $bad [get_seed]]
    }
    if [catch {regexp -all -expanded $re $re}] {
        set good [expr $good + 1]
    } else {
        set bad [expr $bad + 1]
    }
}
