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
    int ovector[32];
    const char *error;
    int erroffset, errorcode, i,x;

    bool seed_generated = false;
    long start = 0, stop = kIter, count = 0;
    if (argc <= 1) {
      fprintf(stderr, "Usage: %s <seed> [[start][stop]]\n", argv[0]);
      exit(1);
    }

    long seed = strtoul(argv[1], NULL, 0);

    if (argc > 2)
       start = strtoul(argv[2], NULL, 0);
    if (argc > 3)
       stop = strtoul(argv[3], NULL, 0);
    long prog = kProg;
    if (argc > 4)
       prog = strtoul(argv[4], NULL, 0);

    srandom(seed);
    size_t len = randomregex(buf, sizeof(buf), random);

    if (start > 0) {
      for (count = 0; count < start; count++) {
        seed = random();
        srandom(seed);
        len = randomregex(buf, sizeof(buf), random);
      }
    }

    int bad = 0,match =0, nomatch = 0;
    printf("starting a %d\n", count);
    fflush(stdout);
    for (; count <= stop; count++) {
      Reprog *re = NULL;
      Resub rs[10];
      int res = 0;
      memset(rs, 0, sizeof(rs));

      if ((count % prog) == 0 || start) {
        printf("sample: %s, flags: %s\n"
               "seed: %lu bad: %d match: %d nomatch: %d total: %d\n",
               buf, "", seed, bad, match, nomatch, count);
        fflush(stdout);
      }

      re = regcomp9(buf);
      if (!re) {
          bad++;
      } else {
        if (regexec9(re, buf, rs, 10)) {
          match++;
        } else {
          nomatch++;
        }
      }

      if (re) free(re);
      // Reseed using next random()
      seed = random();
      srandom(seed);
      len = randomregex(buf, sizeof(buf), random);
    }

      printf("sample: %s, flags: %s\n"
             "seed: %lu bad: %d match: %d nomatch: %d total: %d\n",
             buf, "", seed, bad, match, nomatch, count);
      fflush(stdout);

    return 0;
}

enum {
    REGEXMATCHEDPAIR,
    REGEXESCAPEDCHAR,
    REGEXSPECIALCHAR,
    REGEXQUANTIFY,
    REGEXEXTENSION,
    REGEXREPEATEDCHAR,
    REGEXRANDOM,
    REGEXEND,
    REGEXCHAR,
    REGEXPROPERTY,
    REGEXPOSIX,
    NREGEXTYPES
};

size_t randomregex(char *buf, size_t maxlen, long (* rfunc)(void))
{
    unsigned count = 0;

    if (maxlen == 0) return 0;

    memset(buf, '\0', maxlen);

    while (maxlen--) {
        count++;
        switch (rfunc() % NREGEXTYPES) {
            case REGEXMATCHEDPAIR:
                /* add a matched pair of characters, requires 2 bytes */
                if (maxlen >= 2) {
                    memmove(buf + 1, buf, strlen(buf) + 1);
                    switch (rfunc() % 2) {
                        case 0: buf[0] = '('; strcat(buf, ")"); break;
                        case 1: buf[0] = '['; strcat(buf, "]"); break;
                    }
                    maxlen -= 2;
                    break;
                }
                /* fallthrough */
            case REGEXESCAPEDCHAR:
                /* add one of the supported escaped characters, requires
                 * 2-4 bytes */
                if (maxlen >= 4) {
                    switch (rfunc() % 23) {
                        case 0: strcat(buf, "\\t"); maxlen -= 2; break;
                        case 1: strcat(buf, "\\n"); maxlen -= 2; break;
                        case 2: strcat(buf, "\\r"); maxlen -= 2; break;
                        case 3: strcat(buf, "\\f"); maxlen -= 2; break;
                        case 4: strcat(buf, "\\a"); maxlen -= 2; break;
                        case 5: strcat(buf, "\\e"); maxlen -= 2; break;
                        case 6: strcat(buf, "\\E"); maxlen -= 2; break;
                        case 7: strcat(buf, "\\Q"); maxlen -= 2; break;
                        case 8: strcat(buf, "\\w"); maxlen -= 2; break;
                        case 9: strcat(buf, "\\W"); maxlen -= 2; break;
                        case 10: strcat(buf, "\\s"); maxlen -= 2; break;
                        case 11: strcat(buf, "\\S"); maxlen -= 2; break;
                        case 12: strcat(buf, "\\d"); maxlen -= 2; break;
                        case 13: strcat(buf, "\\D"); maxlen -= 2; break;
                        case 14: strcat(buf, "\\b"); maxlen -= 2; break;
                        case 15: strcat(buf, "\\B"); maxlen -= 2; break;
                        case 16: strcat(buf, "\\A"); maxlen -= 2; break;
                        case 17: strcat(buf, "\\Z"); maxlen -= 2; break;
                        case 18: strcat(buf, "\\z"); maxlen -= 2; break;
                        case 19: strcat(buf, "\\G"); maxlen -= 2; break;
                        case 20: strcat(buf, "\\c["); maxlen -= 3; break;
                        case 21: sprintf(buf + strlen(buf), 
                                        "\\%03o", rfunc() % 257); 
                                maxlen -= 4; break;
                        case 22: sprintf(buf + strlen(buf), 
                                         "\\x%02X", rfunc() % 257); 
                                 maxlen -= 4; break;
                    }
                    break;
                }
                /* fallthrough */
            case REGEXSPECIALCHAR:
                if (maxlen >= 1) {
                    switch (rfunc() % 8) {
                        case 0: strcat(buf, "\\"); break;
                        case 1: strcat(buf, "^"); break;
                        case 2: strcat(buf, "."); break;
                        case 3: strcat(buf, "$"); break;
                        case 4: strcat(buf, "|"); break;
                        case 5: strcat(buf, "*"); break;
                        case 6: strcat(buf, "+"); break;
                        case 7: strcat(buf, "?"); break;
                    }
                    maxlen--;
                    break;
                }
                /* fallthrough */
            case REGEXQUANTIFY:
                if (maxlen >= 9) {
                    strcat(buf, "{"); maxlen--;
                    if (rfunc() % 2)
                        maxlen -= sprintf(buf + strlen(buf), 
                                "%i", rfunc() % 32);
                    if (rfunc() % 2)
                        strcat(buf, ","); maxlen--;
                    if (rfunc() % 2)
                        maxlen -= sprintf(buf + strlen(buf), 
                                "%i", rfunc() % 32);
                    strcat(buf, "}"); maxlen--;
                    break;
                }
                /* fallthrough */
            case REGEXEXTENSION:
                if (maxlen >= 12) {
                    switch(rfunc() % 10) {
                        case 0: strcat(buf, "(?#"); maxlen -= 3; break;
                        case 1: strcat(buf, "(?:"); maxlen -= 3; break;
                        case 2: strcat(buf, "(?"); maxlen -= 2;
                                if (!(rfunc() % 4)) strcat(buf, "i"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "m"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "s"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "x"), maxlen--;
                                if (!(rfunc() % 2)) strcat(buf, "-"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "i"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "m"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "s"), maxlen--;
                                if (!(rfunc() % 4)) strcat(buf, "x"), maxlen--;
                                strcat(buf, ":"); maxlen--;
                                break;
                        case 3: strcat(buf, "(?="); maxlen -= 3; break;
                        case 4: strcat(buf, "(?!"); maxlen -= 3; break;
                        case 5: strcat(buf, "(?<="); maxlen -= 4; break;
                        case 6: strcat(buf, "(?<!"); maxlen -= 4; break;
                        case 7: strcat(buf, "(?{"); maxlen -= 3; break;
                        case 8: strcat(buf, "(?>"); maxlen -= 3; break;
                        case 9: strcat(buf, "(?("); maxlen -= 3; break;
                        case 10: strcat(buf, "(?"); maxlen -= 2; 
                                 if (!(rfunc() % 4)) strcat(buf, "i"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "m"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "s"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "x"), maxlen--;
                                 if (!(rfunc() % 2)) strcat(buf, "-"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "i"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "m"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "s"), maxlen--;
                                 if (!(rfunc() % 4)) strcat(buf, "x"), maxlen--;
                                 break;
                    }
                    break;
                }
                /* fallthrough */
            case REGEXRANDOM: {
                int i, count;
                char l[2] = { 0, 0 };

                for (i = 0, count = rfunc() % 16; i < min(count, maxlen); i++) {
                    l[1] = rfunc() % 256;
                    strcat(buf, l);
                    maxlen--;
                }
                break;
            }
            case REGEXREPEATEDCHAR: {
                long len;
                char l[16];

                memset(l, 0x00, sizeof(l));
                len = rfunc() % sizeof(l);
                memset(l, rfunc() % 256, min(len, maxlen));
                strcat(buf, l);
                maxlen -= strlen(l);
                break;
            }
            case REGEXCHAR: {
                char l[2] = { 0, 0 };
                l[0] = rfunc() % 256;
                if (maxlen >= 1) {
                    strcat(buf, l);
                    maxlen--;
                    break;
                }
            }
            case REGEXPROPERTY:
                if (maxlen >= 9) {
                    strcat(buf, "\\P{"); maxlen -= 3;
                    if (rfunc() % 2) strcat(buf, "^"); maxlen--;
                    switch (rfunc() % 7) {
                        /* long one */
                        case 0: if (maxlen >= 20) {
                                    strcat(buf, "Canadian_Aboriginal}");
                                    maxlen -= 20;
                                }
                                break;
                        /* sample weird ones */
                        case 1: strcat(buf, "Any}"); maxlen -= 4; break;
                        case 2: strcat(buf, "Yi}"); maxlen -= 3; break;
                        case 3: strcat(buf, "C}"); maxlen -= 2; break;
                        case 4: strcat(buf, "Cc}"); maxlen -= 3; break;
                        case 5: strcat(buf, "L&}"); maxlen -= 2; break;
                        case 6: strcat(buf, "w00t}"); maxlen -= 5; break;
                    }
                    break;
                }
              case REGEXPOSIX:
                if (maxlen >= 8) {
                    switch (rfunc() % 4) {
                        case 0: strcat(buf, ":xdigit:"); maxlen -= 8; break;
                        case 1: strcat(buf, ":word:"); maxlen -= 6; break;
                        case 3: strcat(buf, ":print:"); maxlen -= 7; break;
                    }
                } 

            case REGEXEND:
                /* dont want this too early */
                if (count && !(rfunc() % kLength))
                    return strlen(buf);
        }
    }
    return strlen(buf);
}

