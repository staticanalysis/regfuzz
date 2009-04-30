/*
 * Copyright 2007-2009 Google Inc.
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
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <alloca.h>
#include <string.h>
#include <assert.h>

#include "regfuzz.h"

enum {
    REGEXMATCHEDPAIR, /* characters that only make sense in matched pairs */
    REGEXESCAPEDCHAR, /* escaped characters */
    REGEXSPECIALCHAR, /* characters with special meaning */
    REGEXQUANTIFY,    /* quantifiers, eg {m,n} */
    REGEXEXTENSION,   /* special extension */
    REGEXREPEATEDCHAR,/* repeat a random character */
    REGEXRANDOM,      /* random character */
    REGEXEND,         /* possible end of expression */
    REGEXCHAR,        /* random character */
    REGEXPROPERTY,    /* unicode property (perl/pcre) */
    REGEXPOSIX,       /* posix property */
    NREGEXTYPES
};

#define min(x,y) (((x) > (y)) ? (y) : (x))
#define max(x,y) (((x) < (y)) ? (y) : (x))
#define M(buf) (max(maxlen - strlen(buf), 0))

char *randomregex(char *buf, size_t maxlen, uint8_t lenbias, unsigned flags)
{
    /* initialize to zero */
    memset(buf, '\0', maxlen);

    /* sanity checks */
    if (maxlen == 0) return buf;
    if (lenbias == 0) return buf;

    /* allow one for '\0' */
    maxlen--;

    /* fill the buffer up with random regex patterns */
    while (M(buf)) {
        switch (random() % NREGEXTYPES) {
            case REGEXMATCHEDPAIR: {
                /* choose a random offset into the string */
                unsigned offset = random() % (strlen(buf) + 1);
                /* split the string into start and rest */
                char *pre = strndup(buf, offset);
                char *rest = strdup(buf + offset);

                /* add a matched pair of characters, requires 2 or 3 bytes */
                switch (random() % 6) {
                    case 0: snprintf(buf, maxlen, "%s(%s)", pre, rest); break;
                    case 1: snprintf(buf, maxlen, "(%s%s)", pre, rest); break;
                    case 2: snprintf(buf, maxlen, "%s[%s]", pre, rest); break;
                    case 3: snprintf(buf, maxlen, "[%s%s]", pre, rest); break;
                    case 4: snprintf(buf, maxlen, "%s[^%s]", pre, rest); break;
                    case 5: snprintf(buf, maxlen, "[^%s%s]", pre, rest); break;
                }
                free(pre);
                free(rest);
                break;
            }
            case REGEXESCAPEDCHAR: {
                char *tmp = strdup(buf);
                /* add one of the supported escaped characters */
                switch (random() % 36) {
                    case 0: strncat(buf, "\\t", M(buf)); break;
                    case 1: strncat(buf, "\\n", M(buf)); break;
                    case 2: strncat(buf, "\\r", M(buf)); break;
                    case 3: strncat(buf, "\\f", M(buf)); break;
                    case 4: strncat(buf, "\\a", M(buf)); break;
                    case 5: strncat(buf, "\\e", M(buf)); break;
                    /* 257 is deliberate, possibly confuse parser */
                    case 6: snprintf(buf, maxlen, "%s\\%03o", tmp,
                                random() % 257); break;
                    case 7: snprintf(buf, maxlen, "%s\\x%02X", tmp,
                                random() % 257); break;
                    case 8: strncat(buf, "\\c", M(buf)); break;
                    case 9: strncat(buf, "\\l", M(buf)); break;
                    case 10: strncat(buf, "\\u", M(buf)); break;
                    case 11: strncat(buf, "\\L", M(buf)); break;
                    case 12: strncat(buf, "\\U", M(buf)); break;
                    case 13: strncat(buf, "\\E", M(buf)); break;
                    case 14: strncat(buf, "\\Q", M(buf)); break;
                    case 15: strncat(buf, "\\w", M(buf)); break;
                    case 16: strncat(buf, "\\W", M(buf)); break;
                    case 17: strncat(buf, "\\s", M(buf)); break;
                    case 18: strncat(buf, "\\S", M(buf)); break;
                    case 19: strncat(buf, "\\d", M(buf)); break;
                    case 20: strncat(buf, "\\D", M(buf)); break;
                    case 21: strncat(buf, "\\b", M(buf)); break;
                    case 22: strncat(buf, "\\B", M(buf)); break;
                    case 23: strncat(buf, "\\A", M(buf)); break;
                    case 24: strncat(buf, "\\Z", M(buf)); break;
                    case 25: strncat(buf, "\\z", M(buf)); break;
                    case 26: strncat(buf, "\\G", M(buf)); break;
                    case 27: snprintf(buf, maxlen, "%s\\%d", tmp,
                        (random() % 257) * (1 - 2 * (random() % 2))); break;
                    /* 0x1ffff is deliberate */
                    case 28: snprintf(buf, maxlen, "%s\\x{%x}", tmp,
                        random() & 0x1ffff ); break;
                    case 29: strncat(buf, "\\N", M(buf)); break;
                    case 30: strncat(buf, "\\C", M(buf)); break;
                    case 31: strncat(buf, "\\pP", M(buf)); break;
                    case 32: strncat(buf, "\\p", M(buf)); break;
                    case 33: strncat(buf, "\\PP", M(buf)); break;
                    case 34: strncat(buf, "\\P", M(buf)); break;
                    case 35: strncat(buf, "\\X", M(buf)); break;
                }
                free(tmp);
                break;
            }
            case REGEXSPECIALCHAR:
                switch (random() % 9) {
                    case 0: strncat(buf, "\\", M(buf)); break;
                    case 1: strncat(buf, "^", M(buf)); break;
                    case 2: strncat(buf, ".", M(buf)); break;
                    case 3: strncat(buf, "$", M(buf)); break;
                    case 4: strncat(buf, "|", M(buf)); break;
                    case 5: strncat(buf, "*", M(buf)); break;
                    case 6: strncat(buf, "+", M(buf)); break;
                    case 7: strncat(buf, "?", M(buf)); break;
                    case 8: strncat(buf, "-", M(buf)); break;
                    /* maybe close open parens */
                    // case 9: strncat(buf, ")", M(buf)); break;
                }
                break;
            case REGEXQUANTIFY: {
                char *tmp = strdup(buf);
                switch (random() % 5) {
                    /* {42,-42} */
                    case 0: snprintf(buf, maxlen, "%s{%d,%d}", tmp, 
                        (random() % 256) * (1 - 2 * (random() % 2)),
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    /* {42} */
                    case 1: snprintf(buf, maxlen, "%s{%d}", tmp,
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    /* {,42} */ 
                    case 2: snprintf(buf, maxlen, "%s{,%d}", tmp,
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    /* {42,} */
                    case 3: snprintf(buf, maxlen, "%s{%d,}", tmp,
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    /* {} */
                    case 4: snprintf(buf, maxlen, "%s{}", tmp); break;
                }
                free(tmp);
                break;
            }
            case REGEXEXTENSION: {
                /* choose a random offset into the string */
                unsigned offset = random() % (strlen(buf) + 1);
                /* split the string into start and rest */
                char *pre = strndup(buf, offset);
                char *rest = strdup(buf + offset);
                char *split;
                switch(random() % 10) {
                    case 0: snprintf(buf, maxlen, "%s(?#%s)", pre, rest); break;
                    case 1: snprintf(buf, maxlen, "%s(?:%s)", pre, rest); break;
                    case 2: {
                        char flags[128];

                        /* initialise to zero */
                        memset(flags, '\0', sizeof(flags));

                        /* choose some flags to add */
                        if (random() % 4) strcat(flags, "i");
                        if (random() % 4) strcat(flags, "m");
                        if (random() % 4) strcat(flags, "s");
                        if (random() % 4) strcat(flags, "x");
                        if (random() % 2) strcat(flags, "-");
                        if (random() % 4) strcat(flags, "i");
                        if (random() % 4) strcat(flags, "m");
                        if (random() % 4) strcat(flags, "s");
                        if (random() % 4) strcat(flags, "x");

                        /* now add them to the regex */
                        snprintf(buf, maxlen, "%s(?%s:%s)", pre, flags, rest);
                        break;
                    }
                   case 3: snprintf(buf, maxlen, "%s(?=%s)", pre, rest); break;
                   case 4: snprintf(buf, maxlen, "%s(?!%s)", pre, rest); break;
                   case 5: snprintf(buf, maxlen, "%s(?<=%s)", pre, rest); break;
                   case 6: snprintf(buf, maxlen, "%s(?<!%s)", pre, rest); break;
                   case 7: snprintf(buf, maxlen, "%s(?{%s})", pre, rest); break;
                   case 8: snprintf(buf, maxlen, "%s(?>%s)", pre, rest); break;
                   case 10: snprintf(buf, maxlen, "%s(??{%s})", pre, rest); break;                 
                   case 9: 
                        /* conditionals... */
                        offset = random() % (strlen(rest) + 1);
                        split = strndup(rest, offset);
                        snprintf(buf, maxlen, "%s(?(%s)%s)", pre, 
                            split, rest + offset); break;
                        free(split);
                        break;
                }
                free(pre);
                free(rest);
                break;
            }
            case REGEXRANDOM: {
                char str[2] = { '\0', '\0' };
                while (random() % (lenbias / 2 + 1)) {
                    *str = random() % 256;
                    strncat(buf, str, M(buf));
                } 
                break;
            }
            case REGEXREPEATEDCHAR: {
                size_t len = random() % (lenbias * 4 + 1);
                char *tmp = malloc(len + 1);
                memset(tmp, random() % 256, len), tmp[len] = '\0';
                strncat(buf, tmp, M(buf));
                free(tmp);
                break;
            }
            case REGEXCHAR: {
                char str[2] = { random() % 256, 0 };
                strncat(buf, str, M(buf));
                break;
            }
            case REGEXEND:
                /* possibly end the expression, dpending on bias */
                if (random() % lenbias == 0)
                    return buf;
                break;
            case REGEXPOSIX:
                if (flags & POSIX_CHARCLASS) {
                    char *tmp = strdup(buf);
                    snprintf(buf, maxlen, "%s[:%s:]",
                        tmp, posix[random() % (sizeof(posix) / sizeof(*posix))]); break;
                    free(tmp);
                }
                break;
            case REGEXPROPERTY: {
                if (flags & UNICODE_PROPERTIES) {
                    char *tmp = strdup(buf);
                    char *p = (random() % 2) ? "P" : "p";
                    char *neg = (random() % 2) ? "^" : "";
                    snprintf(buf, maxlen, "%s\\%s{%s%s}",
                        tmp, p, neg, ucp[random() % (sizeof(ucp) / sizeof(*ucp))]); break;
                    free(tmp);
                }
                break;
            }
        }
    }
    /* unreachable */
    return buf;
}

void _set_seed(unsigned long s) {
  random();
  seed = s;
  srandom(seed);
}

unsigned long _get_seed() {
  return seed;
}

char *_getregex(unsigned lenbias, unsigned flags) {
   static char regex[8192];
   char *r = randomregex(regex, sizeof(regex), lenbias, flags);
   _set_seed((unsigned long)random());
   return r;
}

#ifdef STANDALONE
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s [seed] [lenbias] [flags]\n", *argv);
        return 1;
    }
    _set_seed(atol(argv[1]));
    fprintf(stdout, "%s", _getregex(atol(argv[2]), atol(argv[3])));
    return 0;
}
#endif
