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

import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class RegexFuzzHarness {

    public static void main(String[] args){
        if (args.length < 2) {
          System.err.println("Args: <seed> <length> [<start> [<end>]]\n");
          System.exit(1);
        }
        Integer seed = Integer.valueOf(args[0]);
        Integer length = Integer.valueOf(args[1]);
        Integer start = 0, end = 65535;
        if (args.length == 3) {
          start = Integer.valueOf(args[2]);
          end = start;
        } else if (args.length > 3) {
          start = Integer.valueOf(args[2]);
          end = Integer.valueOf(args[3]);
        }

        RegexGenerator rg = new RegexGenerator();

        Integer bad_compile = 0;
        Integer bad_exec = 0;
        Integer bad_matcher = 0;
        Integer matched = 0;
        Integer unmatched = 0;
        Integer count = 0;
        String candidate = "";

        if (start != 0) {
          System.out.format("[*] skipping to %d\n", start);
          System.out.flush();
          for (;count < start; ++count) {
            rg.Initialize(seed, length);
            rg.GenerateCandidate();
            seed = rg.random_.nextInt();
          }
        }

        System.out.format("[*] running %d to %d\n", start, end);
        System.out.flush();
        for(;count <= end; count++) {
          rg.Initialize(seed, length);
          candidate = rg.GenerateCandidate();

          if ((count % 1024) == 0 || count.equals(end)) {
            System.out.format(
              "[*] seed: %d total: %d bad_compile:%d bad_exec:%d bad_matcher:%d matched:%d unmatched:%d\n",
              seed, count, bad_compile, bad_exec, bad_matcher, matched, unmatched);
            System.out.format("[*] sample: %s\n", candidate);
            System.out.flush();
          }
          seed = rg.random_.nextInt();

          Pattern pattern;
          try {
            pattern = Pattern.compile(candidate);
          } catch (Exception e) {
            bad_compile++;
            continue;
          }
          Matcher matcher;
          try {
            matcher = pattern.matcher(candidate);
          } catch (Exception e) {
            bad_exec++;
            continue;
          }

          try {
            if (matcher.find())
              matched++;
            else
              unmatched++;
          } catch (Exception e) {
            bad_matcher++;
          }
        }
        System.out.println("[*] done.\n");
        System.out.flush();
    }
}

