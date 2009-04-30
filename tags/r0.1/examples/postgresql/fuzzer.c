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
 *
 *
 * Usage:
 *  drop function generate_regex();
 *  CREATE FUNCTION generate_regex() RETURNS text
 *  AS '/path/to/fuzzer', 'generate_regex'
 *  LANGUAGE C STRICT;
 *
 * drop function get_seed();
 * CREATE FUNCTION get_seed() RETURNS integer
 * AS '/path/to/fuzzer', 'get_seed'
 *   LANGUAGE C STRICT;
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <alloca.h>

#include <postgres.h>

#define min(x,y) (((x) > (y)) ? (y) : (x))


unsigned int seed = 0;

void re_seed(int);
char *randomregex(char *buf, size_t maxlen, uint8_t lenbias);

enum {
    REGEXMATCHEDPAIR, /* characters that only make sense in matched pairs */
    REGEXESCAPEDCHAR, /* escaped characters */
    REGEXSPECIALCHAR, /* characters with special meaning */
    REGEXQUANTIFY,    /* quantifiers, eg {m,n} */
    REGEXEXTENSION,   /* special extension */
    REGEXREPEATEDCHAR,/* repeat a random character */
    REGEXRANDOM,      /* random character */
    REGEXEND,          
    REGEXCHAR,
    REGEXPROPERTY,
    REGEXPOSIX,
    NREGEXTYPES
};

char *randomregex(char *buf, size_t maxlen, uint8_t lenbias)
{
    /* initialize to zero */
    memset(buf, '\0', maxlen);

    /* sanity checks */
    if (maxlen == 0) return buf;
    if (lenbias == 0) return buf;

    /* allow one for '\0' */
    maxlen--;
    
    /* fill the buffer up with random regex patterns */
    while (maxlen) {
        switch (random() % NREGEXTYPES) {
            case REGEXMATCHEDPAIR: {
                char *tmp = strdup(buf);
                /* add a matched pair of characters, requires 2 or 3 bytes */
                switch (random() % 3) {
                    case 0: snprintf(buf, maxlen, "(%s)", tmp); break;
                    case 1: snprintf(buf, maxlen, "[%s]", tmp); break;
                    case 2: snprintf(buf, maxlen, "[^%s]", tmp); break;
                }
                free(tmp);
                break;
            }
            case REGEXESCAPEDCHAR: {
                char *tmp = strdup(buf);
                /* add one of the supported escaped characters */
                switch (random() % 23) {
                    case 0: strncat(buf, "\\t", maxlen - strlen(buf)); break;
                    case 1: strncat(buf, "\\n", maxlen - strlen(buf)); break;
                    case 2: strncat(buf, "\\r", maxlen - strlen(buf)); break;
                    case 3: strncat(buf, "\\f", maxlen - strlen(buf)); break;
                    case 4: strncat(buf, "\\a", maxlen - strlen(buf)); break;
                    case 5: strncat(buf, "\\e", maxlen - strlen(buf)); break;
                    case 6: strncat(buf, "\\E", maxlen - strlen(buf)); break;
                    case 7: strncat(buf, "\\Q", maxlen - strlen(buf)); break;
                    case 8: strncat(buf, "\\w", maxlen - strlen(buf)); break;
                    case 9: strncat(buf, "\\W", maxlen - strlen(buf)); break;
                    case 10: snprintf(buf, maxlen, "%s\\%03o", tmp,
                                random() % 257); break;
                    case 11: snprintf(buf, maxlen, "%s\\x%02X", tmp,
                                random() % 257); break;
                }
                free(tmp);
                break;
            }
            case REGEXSPECIALCHAR:
                switch (random() % 8) {
                    case 0: strncat(buf, "\\", maxlen - strlen(buf)); break;
                    case 1: strncat(buf, "^", maxlen - strlen(buf)); break;
                    case 2: strncat(buf, ".", maxlen - strlen(buf)); break;
                    case 3: strncat(buf, "$", maxlen - strlen(buf)); break;
                    case 4: strncat(buf, "|", maxlen - strlen(buf)); break;
                    case 5: strncat(buf, "*", maxlen - strlen(buf)); break;
                    case 6: strncat(buf, "+", maxlen - strlen(buf)); break;
                    case 7: strncat(buf, "?", maxlen - strlen(buf)); break;
                }
                break;
            case REGEXQUANTIFY: {
                char *tmp = strdup(buf);
                switch (random() % 4) {
                    case 0: snprintf(buf, maxlen, "%s{%d,%d}", tmp, 
                        (random() % 256) * (1 - 2 * (random() % 2)),
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    case 1: snprintf(buf, maxlen, "%s{%d}", tmp,
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    case 2: snprintf(buf, maxlen, "%s{,%d}", tmp,
                        (random() % 256) * (1 - 2 * (random() % 2))); break;
                    case 3: snprintf(buf, maxlen, "%s{}", tmp); break;
                }
                free(tmp);
                break;
            }
            case REGEXEXTENSION:
                switch(random() % 2) {
                    case 0: strncat(buf, "(?#", maxlen - strlen(buf)) ; break;
                    case 1: strncat(buf, "(?:", maxlen - strlen(buf)) ; break;
                }
                break;
            case REGEXRANDOM: {
                char str[2] = { '\0', '\0' };
                while (random() % 4) {
                    *str = random() % 256;
                    strncat(buf, str, maxlen - strlen(buf));
                } 
                break;
            }
            case REGEXREPEATEDCHAR: {
                size_t len = random() % 32;
                char *tmp = malloc(len + 1);
                memset(tmp, random() % 256, len), tmp[len] = '\0';
                strncat(buf, tmp, maxlen - strlen(buf));
                free(tmp);
                break;
            }
            case REGEXCHAR: {
                char str[2] = { random() % 256, 0 };
                strncat(buf, str, maxlen - strlen(buf));
                break;
            }
            case REGEXEND:
                if (random() % lenbias == 0)
                    return buf;
        }
    }
    /* unreachable */
    return buf;
}

/* by reference, variable length */
int get_seed() {
  return seed;
}

void re_seed(int s) {
  srandom(s);
  seed = s;
}

text *
generate_regex()
{
    char buf[8192];

    text *new_t = (text *) palloc(VARHDRSZ + 8192);
    VARATT_SIZEP(new_t) = VARHDRSZ + 8192;
    seed = (unsigned int) random();
    srandom(seed);
    randomregex(buf, 8192, 4);
    memcpy((void *) VARDATA(new_t), /* destination */
           buf,
           strlen(buf));  /* how many bytes */
    return new_t;
}


