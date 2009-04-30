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
-- libregfuzz in sql!  (slow as molasses)
--

-- Global seed for the next_rand()
SET @seed = 0;

-- next_rand()
--
-- Returns a random BIGINT
drop function next_rand;
delimiter //
CREATE FUNCTION next_rand() RETURNS BIGINT
NO SQL
BEGIN
  SET @seed = ((@seed * 9301.0 + 49297.0) % 233280.0);
  RETURN CEIL((@seed/233280.0) * 4294967295.0);
END
  //
delimiter ;

-- randc()
-- 
-- Uses next_rand() return a random CHAR
drop function randc;
delimiter //
CREATE FUNCTION randc() RETURNS CHAR
NO SQL
BEGIN
  RETURN CHAR(FLOOR(next_rand() % 256));
END
  //
delimiter ;


-- generate_regex()
--
-- Returns a randomly generated regular expression string in a
-- TEXT variable.  It relies on next_rand() and randc().
drop function generate_regex;
delimiter //
CREATE FUNCTION generate_regex(length INTEGER) RETURNS TEXT
NO SQL
BEGIN
  DECLARE re TEXT DEFAULT "";
  DECLARE char_count INTEGER DEFAULT 0;
  DECLARE sep CHAR;
  DECLARE c CHAR;

  BUILD: LOOP
    CASE  next_rand() % 10 
    WHEN 0 THEN -- matched pair and word boundaries
      CASE next_rand() % 4
        WHEN 0 THEN SET re = CONCAT("(", CONCAT(re, ")"));
        WHEN 1 THEN SET re = CONCAT("[", CONCAT(re, "]"));
        WHEN 2 THEN SET re = CONCAT("[^", CONCAT(re, "]"));
        WHEN 3 THEN SET re = CONCAT("[[:<:]]", CONCAT(re, "[[:>:]]"));
      END CASE;
    WHEN 1 THEN  -- escaped char
      CASE next_rand() % 17
        WHEN 0 THEN SET re = CONCAT(re, "\\\\b");
        WHEN 1 THEN SET re = CONCAT(re, "\\\\B");
        WHEN 2 THEN SET re = CONCAT(re, "\\\\c");
        WHEN 3 THEN SET re = CONCAT(re, "\\\\d");
        WHEN 4 THEN SET re = CONCAT(re, "\\\\D");
        WHEN 5 THEN SET re = CONCAT(re, "\\\\f");
        WHEN 6 THEN SET re = CONCAT(re, "\\\\n");
        WHEN 7 THEN SET re = CONCAT(re, "\\\\r");
        WHEN 8 THEN SET re = CONCAT(re, "\\\\s");
        WHEN 9 THEN SET re = CONCAT(re, "\\\\S");
        WHEN 10 THEN SET re = CONCAT(re, "\\\\t");
        WHEN 11 THEN SET re = CONCAT(re, "\\\\v");
        WHEN 12 THEN SET re = CONCAT(re, "\\\\w");
        WHEN 13 THEN SET re = CONCAT(re, "\\\\W");
        WHEN 14 THEN SET re = CONCAT(re, "\\\\x");
        WHEN 15 THEN SET re = CONCAT(re, "\\\\u");
        WHEN 16 THEN SET re = CONCAT(re, "\\\\");
      END CASE;
    WHEN 2 THEN -- special char
      CASE next_rand() % 8
        WHEN 0 THEN SET re = CONCAT(re, "\\\\");
        WHEN 1 THEN SET re = CONCAT(re, "^");
        WHEN 2 THEN SET re = CONCAT(re, ".");
        WHEN 3 THEN SET re = CONCAT(re, "$");
        WHEN 4 THEN SET re = CONCAT(re, "|");
        WHEN 5 THEN SET re = CONCAT(re, "*");
        WHEN 6 THEN SET re = CONCAT(re, "+");
        WHEN 7 THEN SET re = CONCAT(re, "?");
      END CASE;
    WHEN 3 THEN -- extension
      CASE next_rand() % 3
        WHEN 0 THEN SET re = CONCAT("(?:", CONCAT(re, ")"));
        WHEN 1 THEN SET re = CONCAT("(?=", CONCAT(re, ")"));
        WHEN 2 THEN SET re = CONCAT("(?!", CONCAT(re, ")"));
      END CASE;
    WHEN 4 THEN -- possible end
      IF (next_rand() % length) = 0 THEN
        LEAVE BUILD;
      END IF;
    WHEN 5 THEN -- repeated random char
      SET c = randc();
      WHILE char_count < (next_rand() % 32) DO
        SET re = CONCAT(re, c);
        SET char_count = char_count + 1;
      END WHILE;
    WHEN 6 THEN -- quantify
      SET re = CONCAT("{", re);
      IF (next_rand() % 8 = 0) THEN
        SET re = CONCAT(re, "-");
      END IF;
      IF (next_rand() % 2 = 0) THEN
        SET re = CONCAT(re, ",");
      END IF;
      IF (next_rand() % 8 = 0) THEN
        SET re = CONCAT(re, "-");
      END IF;
      IF (next_rand() % 2 = 0) THEN
        SET re = CONCAT(re, next_rand() % 32);
      END IF;
      SET re = CONCAT(re, "}");
    WHEN 7 THEN
      SET re = CONCAT(re, randc());
    WHEN 8 THEN -- characters
      CASE next_rand() % 38
        WHEN 0 THEN SET re = CONCAT(re, "[.NUL.]");
        WHEN 1 THEN SET re = CONCAT(re, "[.STX.]");
        WHEN 2 THEN SET re = CONCAT(re, "[.EOT.]");
        WHEN 3 THEN SET re = CONCAT(re, "[.ACK.]");
        WHEN 4 THEN SET re = CONCAT(re, "[.alert.]");
        WHEN 5 THEN SET re = CONCAT(re, "[.SOH.]");
        WHEN 6 THEN SET re = CONCAT(re, "[.ETX.]");
        WHEN 7 THEN SET re = CONCAT(re, "[.ENQ.]");
        WHEN 8 THEN SET re = CONCAT(re, "[.BEL.]");
        WHEN 9 THEN SET re = CONCAT(re, "[.BS.]");
        WHEN 10 THEN SET re = CONCAT(re, "[.HT.]");
        WHEN 11 THEN SET re = CONCAT(re, "[.LF.]");
        WHEN 12 THEN SET re = CONCAT(re, "[.VT.]");
        WHEN 13 THEN SET re = CONCAT(re, "[.FF.]");
        WHEN 14 THEN SET re = CONCAT(re, "[.CR.]");
        WHEN 15 THEN SET re = CONCAT(re, "[.SO.]");
        WHEN 16 THEN SET re = CONCAT(re, "[.DLE.]");
        WHEN 17 THEN SET re = CONCAT(re, "[.SI.]");
        WHEN 18 THEN SET re = CONCAT(re, "[.DC1.]");
        WHEN 19 THEN SET re = CONCAT(re, "[.DC2.]");
        WHEN 20 THEN SET re = CONCAT(re, "[.DC3.]");
        WHEN 21 THEN SET re = CONCAT(re, "[.DC4.]");
        WHEN 22 THEN SET re = CONCAT(re, "[.NAK.]");
        WHEN 23 THEN SET re = CONCAT(re, "[.SYN.]");
        WHEN 24 THEN SET re = CONCAT(re, "[.ETB.]");
        WHEN 25 THEN SET re = CONCAT(re, "[.CAN.]");
        WHEN 26 THEN SET re = CONCAT(re, "[.EM.]");
        WHEN 27 THEN SET re = CONCAT(re, "[.SUB.]");
        WHEN 28 THEN SET re = CONCAT(re, "[.IS4.]");
        WHEN 29 THEN SET re = CONCAT(re, "[.IS3.]");
        WHEN 30 THEN SET re = CONCAT(re, "[.IS2.]");
        WHEN 31 THEN SET re = CONCAT(re, "[.IS1.]");
        WHEN 32 THEN SET re = CONCAT(re, "[.ESC.]");
        WHEN 33 THEN SET re = CONCAT(re, "[.FS.]");
        WHEN 34 THEN SET re = CONCAT(re, "[.GS.]");
        WHEN 35 THEN SET re = CONCAT(re, "[.RS.]");
        WHEN 36 THEN SET re = CONCAT(re, "[.US.]");
        WHEN 37 THEN SET re = CONCAT(re, "[.DEL.]");
      END CASE;
    WHEN 9 THEN -- character or equivalence class
      CASE next_rand() % 2
        WHEN 0 THEN SET sep = ":";
        WHEN 1 THEN SET sep = "=";
      END CASE;
      CASE next_rand() % 12
        WHEN 0 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "alnum"), sep));
        WHEN 1 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "alpha"), sep));
        WHEN 2 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "blank"), sep));
        WHEN 3 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "cntrl"), sep));
        WHEN 4 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "digit"), sep));
        WHEN 5 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "graph"), sep));
        WHEN 6 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "lower"), sep));
        WHEN 7 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "print"), sep));
        WHEN 8 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "punct"), sep));
        WHEN 9 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "space"), sep));
        WHEN 10 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "upper"), sep));
        WHEN 11 THEN SET re = CONCAT(re, CONCAT(CONCAT(sep, "xdigit"), sep));
      END CASE;
    END CASE;
  END LOOP;

  RETURN re;
END
//
delimiter ;

-- fuzz()
--
-- Fuzzes the REGEXP command using random regular expressions
-- generated by generate_regex()
drop procedure fuzz;
delimiter //
CREATE PROCEDURE fuzz(seed BIGINT, iterations INTEGER, progress_cnt INTEGER, length_bias INTEGER)
BEGIN
  -- Setup an exception handler for regexp errors (1139)
  DECLARE re TEXT DEFAULT "";
  DECLARE bad, count, matches, matched INTEGER DEFAULT 0;
  DECLARE CONTINUE HANDLER FOR 1139 SET bad = bad + 1;

  -- Set the seed to the user-specified seed
  SET @seed = seed;

  WHILE count < iterations DO
    IF (count % progress_cnt) = 0 THEN
      SELECT count, FORMAT(@seed,0), matches, bad, HEX(re);
    END IF;
    SET re = generate_regex(length_bias);
    SELECT re REGEXP re INTO matched;
    IF matched = 1 THEN
      SET matches = matches + 1;
      SET matched = 0;
    END IF;
    SET count = count + 1;
  END WHILE;
END
  //
delimiter ;

