let x = 5

let blessed_keys =
  [ "PkgName"; "InstalledVersion"; "FixedVersion" ]

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

(* let rearrange_names lists = *)
let each_alist alist =
  let open Etude.Option in
  let+ name = List.assoc_opt "PkgName" alist >>= safe_head
  and+ fixed_versions = List.assoc_opt "FixedVersion" alist
  and+ installed_version =
    List.assoc_opt "InstalledVersion" alist
  in
  let sort =
    List.sort Prelude.(on compare version_of_string)
  in
  ((name, installed_version), sort fixed_versions)

let coalesce_lists lists =
  let open Prelude.List.Assoc in
  let open Etude.Option in
  map coalesce (traverse each_alist lists)

(* let get_next current versions = *)
let versions_example =
  [ [ "4.2.30"; "5.2.13"; "6.0.4" ];
    [ "4.2.30"; "5.2.13"; "6.0.4" ];
    [ "4.2.30"; "5.2.13"; "6.0.4" ];
    [ "5.2.14"; "6.0.5" ];
    [ "5.2.14"; "6.0.5" ];
    [ "4.2.30"; "5.2.13"; "6.0.4" ];
    [ "4.2.30"; "5.2.13"; "6.0.4" ];
    [ "5.2.14"; "6.0.5" ];
    [ "5.2.15"; "6.0.6" ]
  ]

(* let coalesce_lists lists =
 *   let open Etude.Option in
 *   let+ traversed = traverse each_alist in
 *   coalesce traversed *)

(* jq command *)
(* trivy fs --quiet --scanners vuln --format json library_website | jq '.Results[]?.Vulnerabilities | select (. != null)[] | {"PkgName" : .PkgName, "InstalledVersion" : .InstalledVersion, "FixedVersion": .FixedVersion, "Severity" : .Severity }' | jq -n '[inputs]' > cvebump/example.json *)

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
