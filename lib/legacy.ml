let version_compare = Prelude.(on compare version_of_string)
let ( ->- ) x y = version_compare x y = 1

let blessed_keys =
  [ "PkgName"; "InstalledVersion"; "FixedVersion"; "References"; ]

let string_to_string =
  let split s = Prelude.String.split ~sep:", " s in
  function
  | k, `String v when List.mem k blessed_keys ->
    Some (k, split v)
  | _ -> None

let obj_to_alist =
  let open Etude.Option in
  function
  | `O obj -> List.map string_to_string obj |> cat_options
  | _ -> []

let arr_to_list = function
  | `A arr -> List.map obj_to_alist arr
  | _ -> []

let safe_head = function
  | x :: _ -> Some x
  | _ -> None

let each_alist alist =
  let open Etude.Option in
  let+ name = List.assoc_opt "PkgName" alist >>= safe_head
  and+ fixed_versions = List.assoc_opt "FixedVersion" alist
  and+ installed_version =
    List.assoc_opt "InstalledVersion" alist >>= safe_head
  in
  let sort = List.sort version_compare in
  ((name, installed_version), sort fixed_versions)

let coalesce_lists lists =
  let open Prelude.List.Assoc in
  let open Etude.Option in
  map coalesce (traverse each_alist lists)

let each_list current versions =
  let ordering x = x ->- current in
  List.filter ordering versions |> safe_head

let get_nexts current versionses =
  let open Etude.Option in
  traverse (each_list current) versionses

let get_version current versionses =
  let open Etude.Option in
  let get_max =
    Prelude.maximumBy ~compare:version_compare
  in
  let+ nexts = get_nexts current versionses in
  get_max nexts

let lists_to_report lists =
  let open Etude.Option in
  let each_pair ((name, current), versions) =
    let+ version = get_version current versions in
    (name, current, version)
  in
  let* coalesced = coalesce_lists lists in
  traverse each_pair coalesced

let string_to_report json_string =
  json_string
  |> Ezjsonm.from_string
  |> arr_to_list
  |> lists_to_report

let main () =
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
  match string_to_report json_string with
  | Some alist -> alist |> create_output |> print_string
  | _ -> print_endline json_string
