-- Copyright 2007-2009 Google Inc.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Native PL/pgSQL Regular Expression Fuzzer

-- Setup a global state table
drop table fuzzer;
create table fuzzer ( seed BIGINT );
-- Set default seed
insert into fuzzer values ( 100 );


CREATE LANGUAGE plpgsql;

-- next_rand()
--
-- Returns a random BIGINT

CREATE OR REPLACE FUNCTION next_rand() RETURNS BIGINT as $$
DECLARE
  s numeric;
BEGIN
  SELECT INTO s seed from fuzzer LIMIT 1;
  s := ((s * 9301.0 + 49297.0) % 233280.0);
  UPDATE fuzzer SET seed = s;
  RETURN ceiling(((s/233280.0) * 4294967295.0) % 4294967296);
END;
$$ LANGUAGE plpgsql;

-- randc()
-- 
-- Uses next_rand() return a random CHAR
CREATE OR REPLACE FUNCTION randc() RETURNS CHAR AS $$
BEGIN
  RETURN CHR(CAST(floor(next_rand() % 256) as INTEGER));
END;
$$ LANGUAGE plpgsql;


-- generate_regex()
--
-- Returns a randomly generated regular expression string in a
-- TEXT variable.  It relies on next_rand() and randc().
CREATE OR REPLACE FUNCTION generate_regex(length INTEGER) RETURNS TEXT AS $$
DECLARE
  re TEXT := '';
  char_count INTEGER;
  sep CHAR;
  c CHAR;
  pick NUMERIC;
BEGIN
  LOOP
    pick := next_rand() % 10;
    IF pick = 0 THEN
      pick := next_rand() % 4;
      IF pick = 0 THEN re := '(' || re || ')';
      ELSIF pick = 1 THEN re := '[' || re || ']';
      ELSIF pick = 2 THEN re := '[^' || re || ']';
      ELSIF pick = 3 THEN re := '[[:<:]]' || re || '[[:>:]]';
      END IF;
    ELSIF pick = 1 THEN  -- escaped char
      pick := next_rand() % 17;
      IF pick = 0 THEN re := re || '\\\\b';
      ELSIF pick = 1 THEN re := re || '\\\\B';
      ELSIF pick = 2 THEN re := re || '\\\\c';
      ELSIF pick = 3 THEN re := re || '\\\\d';
      ELSIF pick = 4 THEN re := re || '\\\\D';
      ELSIF pick = 5 THEN re := re || '\\\\f';
      ELSIF pick = 6 THEN re := re || '\\\\n';
      ELSIF pick = 7 THEN re := re || '\\\\r';
      ELSIF pick = 8 THEN re := re || '\\\\s';
      ELSIF pick = 9 THEN re := re || '\\\\S';
      ELSIF pick = 10 THEN re := re || '\\\\t';
      ELSIF pick = 11 THEN re := re || '\\\\v';
      ELSIF pick = 12 THEN re := re || '\\\\w';
      ELSIF pick = 13 THEN re := re || '\\\\W';
      ELSIF pick = 14 THEN re := re || '\\\\x';
      ELSIF pick = 15 THEN re := re || '\\\\u';
      ELSIF pick = 16 THEN re := re || '\\\\';
      END IF;
    ELSIF pick = 2 THEN -- special char
      pick := next_rand() % 8;
      IF pick = 0 THEN re := re || '\\\\';
      ELSIF pick = 1 THEN re := re || '^';
      ELSIF pick = 2 THEN re := re || '.';
      ELSIF pick = 3 THEN re := re || '$';
      ELSIF pick = 4 THEN re := re || '|';
      ELSIF pick = 5 THEN re := re || '*';
      ELSIF pick = 6 THEN re := re || '+';
      ELSIF pick = 7 THEN re := re || '?';
      END IF;
    ELSIF pick = 3 THEN -- extension
      pick := next_rand() % 3;
      IF pick = 0 THEN re := '(?:' || re || ')';
      ELSIF pick = 1 THEN re := '(?=' || re || ')';
      ELSIF pick = 2 THEN re := '(?!' || re || ')';
      END IF;
    ELSIF pick = 4 THEN -- possible end
      IF (next_rand() % length) = 0 THEN
        re := ')' || re;
        IF next_rand() % 2 = 0 THEN re := 'b' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'c' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'e' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'i' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'm' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'n' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'p' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'q' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 's' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 't' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'w' || re; END IF;
        IF next_rand() % 2 = 0 THEN re := 'x' || re; END IF;
        re := '***(?' || re;
        EXIT;
      END IF;
    ELSIF pick = 5 THEN -- repeated random char
      c := randc();
      char_count := 0;
      WHILE char_count < (next_rand() % 32) LOOP
        re := re || c;
        char_count := char_count + 1;
      END LOOP;
    ELSIF pick = 6 THEN -- quantify
      re := '{' || re;
      IF (next_rand() % 8 = 0) THEN
        re := re || '-';
      END IF;
      IF (next_rand() % 2 = 0) THEN
        re := re || ',';
      END IF;
      IF (next_rand() % 8 = 0) THEN
        re := re || '-';
      END IF;
      IF (next_rand() % 2 = 0) THEN
        re := re || (next_rand() % 32);
      END IF;
      re := re || '}';
    ELSIF pick = 7 THEN
      re := re || randc();
    ELSIF pick = 8 THEN -- characters
      pick := next_rand() % 38;
      IF pick = 0 THEN re := re || '[.NUL.]';
      ELSIF pick = 1 THEN re := re || '[.STX.]';
      ELSIF pick = 2 THEN re := re || '[.EOT.]';
      ELSIF pick = 3 THEN re := re || '[.ACK.]';
      ELSIF pick = 4 THEN re := re || '[.alert.]';
      ELSIF pick = 5 THEN re := re || '[.SOH.]';
      ELSIF pick = 6 THEN re := re || '[.ETX.]';
      ELSIF pick = 7 THEN re := re || '[.ENQ.]';
      ELSIF pick = 8 THEN re := re || '[.BEL.]';
      ELSIF pick = 9 THEN re := re || '[.BS.]';
      ELSIF pick = 10 THEN re := re || '[.HT.]';
      ELSIF pick = 11 THEN re := re || '[.LF.]';
      ELSIF pick = 12 THEN re := re || '[.VT.]';
      ELSIF pick = 13 THEN re := re || '[.FF.]';
      ELSIF pick = 14 THEN re := re || '[.CR.]';
      ELSIF pick = 15 THEN re := re || '[.SO.]';
      ELSIF pick = 16 THEN re := re || '[.DLE.]';
      ELSIF pick = 17 THEN re := re || '[.SI.]';
      ELSIF pick = 18 THEN re := re || '[.DC1.]';
      ELSIF pick = 19 THEN re := re || '[.DC2.]';
      ELSIF pick = 20 THEN re := re || '[.DC3.]';
      ELSIF pick = 21 THEN re := re || '[.DC4.]';
      ELSIF pick = 22 THEN re := re || '[.NAK.]';
      ELSIF pick = 23 THEN re := re || '[.SYN.]';
      ELSIF pick = 24 THEN re := re || '[.ETB.]';
      ELSIF pick = 25 THEN re := re || '[.CAN.]';
      ELSIF pick = 26 THEN re := re || '[.EM.]';
      ELSIF pick = 27 THEN re := re || '[.SUB.]';
      ELSIF pick = 28 THEN re := re || '[.IS4.]';
      ELSIF pick = 29 THEN re := re || '[.IS3.]';
      ELSIF pick = 30 THEN re := re || '[.IS2.]';
      ELSIF pick = 31 THEN re := re || '[.IS1.]';
      ELSIF pick = 32 THEN re := re || '[.ESC.]';
      ELSIF pick = 33 THEN re := re || '[.FS.]';
      ELSIF pick = 34 THEN re := re || '[.GS.]';
      ELSIF pick = 35 THEN re := re || '[.RS.]';
      ELSIF pick = 36 THEN re := re || '[.US.]';
      ELSIF pick = 37 THEN re := re || '[.DEL.]';
      END IF;
    ELSIF pick = 9 THEN -- character or equivalence class
      pick := next_rand() % 2;
      IF pick = 0 THEN sep := ':';
      ELSIF pick = 1 THEN sep := '=';
      END IF;
      pick := next_rand() % 12;
      IF pick = 0 THEN re :=  re || sep || 'alnum' || sep;
      ELSIF pick = 1 THEN re :=  re || sep || 'alpha' || sep;
      ELSIF pick = 2 THEN re :=  re || sep || 'blank' || sep;
      ELSIF pick = 3 THEN re :=  re || sep || 'cntrl' || sep;
      ELSIF pick = 4 THEN re :=  re || sep || 'digit' || sep;
      ELSIF pick = 5 THEN re :=  re || sep || 'graph' || sep;
      ELSIF pick = 6 THEN re :=  re || sep || 'lower' || sep;
      ELSIF pick = 7 THEN re :=  re || sep || 'print' || sep;
      ELSIF pick = 8 THEN re :=  re || sep || 'punct' || sep;
      ELSIF pick = 9 THEN re :=  re || sep || 'space' || sep;
      ELSIF pick = 10 THEN re :=  re || sep || 'upper' || sep;
      ELSIF pick = 11 THEN re :=  re || sep || 'xdigit' || sep;
      END IF;
    END IF;
  END LOOP;

  RETURN re;
END;
$$ LANGUAGE plpgsql;

-- fuzz()
--
-- Fuzzes the REGEXP command using random regular expressions
-- generated by generate_regex()
CREATE OR REPLACE FUNCTION fuzz(s BIGINT, iterations BIGINT, progress_cnt BIGINT, length_bias INTEGER) RETURNS INTEGER AS $$
DECLARE
  -- Setup an exception handler for regexp errors (1139)
  re TEXT := '';
  bad INTEGER := 0;
  count INTEGER := 0;
  matches INTEGER := 0;
  nomatches INTEGER := 0;
  matched boolean;
  current_seed BIGINT;
BEGIN

  -- Set the seed to the user-specified seed
  UPDATE fuzzer SET seed = s;

  WHILE count < iterations LOOP
    IF (count % progress_cnt) = 0 THEN
      SELECT INTO current_seed seed from fuzzer;
      RAISE INFO 'count: % seed: % matches: % nomatches: % bad: % re: %', count, current_seed, matches, nomatches, bad, re;
    END IF;
    re := generate_regex(length_bias);
    -- TODO: add support to exercise multi-byte regex matches
    BEGIN
      SELECT INTO matched re ~ re;
      IF matched = 't' THEN
        matches := matches + 1;
      ELSE
        nomatches := nomatches + 1;
      END IF;

    EXCEPTION WHEN invalid_regular_expression THEN
        bad := bad + 1;
    END;
    count := count + 1;
  END LOOP;
  RETURN 0;
END;
$$ LANGUAGE plpgsql;
