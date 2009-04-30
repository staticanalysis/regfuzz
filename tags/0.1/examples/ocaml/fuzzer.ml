(*
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
 * libregfuzz bindings
 *
 *)
open Printf ;;
open Swig ;;
open Regfuzz ;;
#load "str.cma" ;;


let lenbias = C_int 3 ;;
let opts = C_int 65535 ;;
let max = ref 128000 ;;
let prog = ref 4096 ;;


let set_seed i =
  let _ = _set_seed (C_int i) in
    printf "seed set to %i\n" i
;;

let set_prog i =
  prog := i
;;

let set_max i =
  max := i
;;



let args = Array.length Sys.argv in
  match args with
| 1 -> set_seed (Random.int 786328);
| 2 -> set_seed (int_of_string Sys.argv.(1))
| 3 -> set_prog (int_of_string Sys.argv.(2));
       set_seed (int_of_string Sys.argv.(1));
| 4 -> set_max (int_of_string Sys.argv.(3));
       set_prog (int_of_string Sys.argv.(2));
       set_seed (int_of_string Sys.argv.(1))
| _ -> raise (Failure "Usage:\n regfuzz fuzz.ml [<seed> <prog> <max>]\n")
;;

let matches = ref 0 in
let nomatches = ref 0 in
let bad = ref 0 in
for count = 0 to !max do
 let re = get_string (_getregex (C_list [ lenbias ; opts ])) in
   try
     if ( Str.string_match (Str.regexp re) re 0 ) == true then
       incr matches
     else
       incr nomatches
     ;
    with Failure e -> incr bad ;
    if ( count mod !prog ) == 0 then
      printf "count: %i seed: %i matches: %i nomatches: %i bad: %i re: %s\n" 
        count (get_int (_get_seed C_void)) !matches !nomatches !bad re; flush stdout
done;;
