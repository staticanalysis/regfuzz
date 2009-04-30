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
 * libregfuzz in java
 */

import java.util.Random;
import java.lang.Math;

public class RegexGenerator {
  public Random random_;
  private Integer length_;

  public void Initialize(Integer seed, Integer length){
    random_ = new Random(seed);
    length_ = length;
  }

  private Integer Next() {
    return Math.abs(random_.nextInt());
  }

  public String GenerateCandidate(){
    String candidate = "";
    while (true) {
      Integer pick = Next() %  9;
      switch (pick) {
        case 0:
          switch (Next() % 5) {
            case 0: candidate = "(" + candidate + ")"; break;
            case 1: candidate = "[" + candidate + "]"; break;
            case 2: candidate = "&&" + candidate; break;
            case 3: candidate = "[^" + candidate + "]"; break;
            case 4: candidate = "\\Q" + candidate + "\\E"; break; /* XXX? */
          }
          break;
        case 1:
          switch (Next() % 21) {
            case 1: candidate += "\\A"; break;
            case 2: candidate += "\\b"; break;
            case 3: candidate += "\\B"; break;
            case 4: candidate += "\\e"; break;
            case 5: candidate += "\\G"; break;
            case 6: candidate += "\\z"; break;
            case 7: candidate += "\\Z"; break;
            case 8: candidate += "\\n"; break;
            case 9: candidate += "\\f"; break;
            case 10: candidate += "\\r"; break;
            case 11: candidate += "\\s"; break;
            case 12: candidate += "\\S"; break;
            case 13: candidate += "\\t"; break;
            case 14: candidate += "\\w"; break;
            case 15: candidate += "\\W"; break;
            case 16: candidate += "\\"; break; /* XXX */
            case 17: candidate += "\\0"; break; /* XXX */ 
            case 18: candidate += "\\x"; break; /* XXX */ 
            case 19: candidate += "\\u"; break; /* XXX */ 
            case 20: candidate += "\\c"; break; /* XXX */ 
          }
          break;
        case 2:
          switch (Next() % 8) {
            case 0: candidate += "\\"; break;
            case 1: candidate += "^"; break;
            case 2: candidate += "."; break;
            case 3: candidate += "$"; break;
            case 4: candidate += "|"; break;
            case 5: candidate += "*"; break;
            case 6: candidate += "+"; break;
            case 7: candidate += "?"; break;
          }
          break;
        case 3:
          switch (Next() % 14) {
            case 0: candidate = "(?:" + candidate + ")"; break;
            case 1: candidate = "(?=" + candidate + ")"; break;
            case 2: candidate = "(?!" + candidate + ")"; break;
            case 3: candidate = "(?<=" + candidate + ")"; break;
            case 4: candidate = "(?<!" + candidate + ")"; break;
            case 5: candidate = "(?>" + candidate + ")"; break;
            case 7: candidate += "(?i)"; /* XXX */ break;
            case 8: candidate += "(?d)"; /* XXX */ break;
            case 9: candidate += "(?m)"; /* XXX */ break;
            case 10: candidate += "(?s)"; /* XXX */ break;
            case 11: candidate += "(?u)"; /* XXX */ break;
            case 12: candidate += "(?x)"; /* XXX */ break;
            case 13: candidate = "(?m:" + candidate + ")"; break;
          }
          break;
        case 4:
          String t = String.format("%c", Next() % 256);
          for (Integer i = 0; i < Next() % 32; i++)
              candidate += t;
           break;
        case 5:
          candidate += "{";
          if (Next() % 8 == 0) 
              candidate += "-"; 
          if (Next() % 2 == 0) 
              candidate = candidate + (Next() % 32);
          if (Next() % 2 == 0)
              candidate += ",";
          if (Next() % 8 == 0)
              candidate += "-";
          if (Next() % 2 == 0)
              candidate = candidate + (Next() % 32);
          candidate += "}";
          break;
        case 6:
          candidate += String.format("%c", Next() % 258);
          break;
        case 7:
          switch (Next() % 18) {
            case 0: candidate += "\\p{Lower}"; break;
            case 1: candidate += "\\p{Upper}"; break;
            case 2: candidate += "\\p{ASCII}"; break;
            case 3: candidate += "\\p{Alpha}"; break;
            case 4: candidate += "\\p{Digit}"; break;
            case 5: candidate += "\\p{Alnum}"; break;
            case 6: candidate += "\\p{Punct}"; break;
            case 7: candidate += "\\p{Graph}"; break;
            case 8: candidate += "\\p{Print}"; break;
            case 9: candidate += "\\p{Blank}"; break;
            case 10: candidate += "\\p{Cntrl}"; break;
            case 11: candidate += "\\p{XDigit}"; break;
            case 12: candidate += "\\p{Space}"; break;
            case 13: candidate += "\\p{InGreek}"; break;
            case 14: candidate += "\\p{Lu}"; break;
            case 15: candidate += "\\p{Sc}"; break;
            case 16: candidate += "\\P{InGreek}"; break;
            case 17: candidate += "[\\p{L}&&[^\\p{Lu}]]"; break;
          }
          break;
        case 8:
          if ((Next() % length_) == 0)
            return candidate;
      }
    }
  }
}

