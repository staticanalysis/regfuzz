/* Copyright 2007-2009 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib9.h"
#include <regexp9.h>

#define min(x,y) (((x) > (y)) ? (y) : (x))

size_t randomregex(char *buf, size_t maxlen, long (* rfunc)(void));

void alarmclock(int n) { asm("int3"); }

static const int kLength = 4; // length bias
static const int kIter = 0xfffff; // number of loops
static const int kProg = 0x1000; // progress indicator frequency

int main(int argc, char **argv)
{
    char buf[8192];
    const char *error;
    int erroffset, errorcode, i,x;
    Reprog *re = NULL;
    Resub rs[10];
    int res = 0;

    bool seed_generated = false;
    long start = 0, stop = kIter, count = 0;

    gets(buf);

    memset(rs, 0, sizeof(rs));
    re = regcomp9(buf);
    if (re) {
      if (regexec9(re, buf, rs, 10)) {
        printf("matched\n");
      }
    }
    if (re) free(re);
    return 0;
}
