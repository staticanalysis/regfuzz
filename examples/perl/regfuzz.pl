#!/usr/bin/perl
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

use regfuzz;
use URI::Escape;

$lenbias = 8;
$progress = 2048;
$offset = 0;
$max = $ARGV[1];

regfuzz::set_seed(int($ARGV[0]));

$count = $matches = $bad = 0;

for ($count = 0; $count < $max; $count++) {
    $regex = regfuzz::getregex($lenbias, (1<<1) | (1<<12));
    print uri_escape($regex)."\n" if $count > 55555;
    eval { 
        $matches++ if grep /$regex/, $regex;
    };
    $bad++ if $@;
    if ($count % $progress == 0) {
        print "count:".$count.", ".
              "match:".$matches.", ".
              "bad:".$bad.", ".
              "seed:".regfuzz::get_seed().", ".
              "\n";
    }
}
exit 0;
