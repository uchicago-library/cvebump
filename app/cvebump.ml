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
  let create_output alist =
    List.map each_row alist |> Prelude.join ~sep:"\n"
  in
  match Lib.Process.string_to_report json_string with
  | Some alist -> alist |> create_output |> print_string
  | _ -> print_endline json_string

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
