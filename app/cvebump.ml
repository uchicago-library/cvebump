let () =
  let open In_channel in
  let json_string = input_all stdin in
  let each_row (name, installed, fixed) =
    Printf.sprintf
      "package: %s\n\
       installed version: %s\n\
       fixed version: %s\n\
       %!"
      name installed fixed
  in
  match Lib.Process.string_to_report json_string with
  | Some alist ->
    print_string
      (Prelude.join ~sep:"\n" @@ List.map each_row alist)
  | _ -> print_endline json_string

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
