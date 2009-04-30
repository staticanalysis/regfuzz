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
 *
 * Javascript regular expression fuzzer tailored for acroread
 */
var length = 8; /* higher favours longer regex, useful range: about 4 - 32 */
var iter = 0xFFFF; /* how many regex to compile and execute */
var prog = 0x100; /* how often to print status messages */
var clear = 0x200; /* how often to clear status messages */


console.show();

function log(msg) {
  console.println(msg);
}

var seed = Math.random();
var maybe_seed = app.response("Enter seed (blank for " + seed + ")");
if (maybe_seed.length == 0) {
  randomNumberGenerator.seed = seed;
} else  {
  randomNumberGenerator.seed = maybe_seed;
}

log("initial seed: " +  randomNumberGenerator.seed);

function randomNumberGenerator() {
            randomNumberGenerator.seed = 
                        (randomNumberGenerator.seed * 9301 + 49297) % 233280;
                                return randomNumberGenerator.seed / (233280.0);
};

function randomNumber() {
            return Math.ceil(randomNumberGenerator() * 4294967295);
};

function randomRegularExpression()
{
    var regex = "";

    while (true) {
        switch (randomNumber() % 8) {
            case 0: /* matched pair */
                switch (randomNumber() % 3) {
                    case 0: regex = "(" + regex + ")"; break;
                    case 1: regex = "[" + regex + "]"; break;
                    case 2: regex = "[^" + regex + "]"; break;
                }
                break;
            case 1: /* escaped char */
                switch (randomNumber() % 17) {
                    case 0: regex += "\\\\b"; break;
                    case 1: regex += "\\\\B"; break;
                    case 2: regex += "\\\\c"; break;
                    case 3: regex += "\\\\d"; break;
                    case 4: regex += "\\\\D"; break;
                    case 5: regex += "\\\\f"; break;
                    case 6: regex += "\\\\n"; break;
                    case 7: regex += "\\\\r"; break;
                    case 8: regex += "\\\\s"; break;
                    case 9: regex += "\\\\S"; break;
                    case 10: regex += "\\\\t"; break;
                    case 11: regex += "\\\\v"; break;
                    case 12: regex += "\\\\w"; break;
                    case 13: regex += "\\\\W"; break;
                    case 14: regex += "\\\\x"; break; /* XXX */
                    case 15: regex += "\\\\u"; break; /* XXX */
                    case 16: regex += "\\\\"; break; /* XXX */ 
                }
                break;
            case 2: /* special char */
                switch (randomNumber() % 8) {
                    case 0: regex += "\\\\"; break;
                    case 1: regex += "^"; break;
                    case 2: regex += "."; break;
                    case 3: regex += "$"; break;
                    case 4: regex += "|"; break;
                    case 5: regex += "*"; break;
                    case 6: regex += "+"; break;
                    case 7: regex += "?"; break;
                }
                break;
            case 3: /* extension */
                switch (randomNumber() % 3) {
                    case 0: regex = "(?:" + regex + ")";
                    case 1: regex = "(?=" + regex + ")";
                    case 2: regex = "(?!" + regex + ")";
                }
                break;
            case 4: /* possible end */
                if ((randomNumber() % length) == 0)
                    return regex;
            case 5: /* repeated random character */
                var t = String.fromCharCode((randomNumber() % 256));
                for (var i = 0; i < randomNumber() % 32; i++)
                    regex += t;
                break;
            case 6: /* quantify */
                regex += "{";
                if (randomNumber() % 8 == 0) 
                    regex += "-"; 
                if (randomNumber() % 2 == 0) 
                    regex = regex + (randomNumber() % 32);
                if (randomNumber() % 2 == 0)
                    regex += ",";
                if (randomNumber() % 8 == 0)
                    regex += "-";
                if (randomNumber() % 2 == 0)
                    regex = regex + (randomNumber() % 32);
                regex += "}";
                break;
            case 7: /* single random character */
                regex += String.fromCharCode((randomNumber() % 256));
                break;
        }
    }
}

var count = 0;
var match = 0;
var nomatch = 0;
var bad = 0;
var flags = new Array(
        "gim",
        "gi",
        "gm",
        "g",
        "im",
        "m",
        "i",
        ""
    );

for (var count = 0; count < iter; count++) {
    var curseed =  randomNumberGenerator.seed;
    var s = randomRegularExpression();
    var f = flags[randomNumber() % flags.length];

    if ((count % clear) == 0) {
      console.clear();
    }
    if ((count % prog) == 0) {
        log("sample: " + escape(s) + ", flags: " + f);
        log("seed: " + curseed + " bad: " + bad + ", match: " + match + ", nomatch: " + nomatch + ", total: " + count);
    }

    try {
        var r = new RegExp(s, f);
        if (r.test(s)) {
            match++;
        } else {
            nomatch++;
        }
    } catch (e) {
        bad++
    }
}

log("sample: " + s + ", flags: " + flags[randomNumber() % flags.length]);
log("bad: " + bad + ", match: " + match + ", nomatch: " + nomatch + ", total: " + count);
log("done.");

