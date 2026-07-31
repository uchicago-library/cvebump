let x = 5

let blessed_keys = [ "PkgName"; "InstalledVersion"; "FixedVersion" ]

let string_to_string =
  let split s = Prelude.String.split ~sep:", " s in
  function
  | (k, `String v) when List.mem k blessed_keys ->
     Some (k, split v)
  | _ -> None

let obj_to_alist =
  let open Etude.Option in
  function | `O obj ->
              List.map string_to_string obj
              |> cat_options
           | _ -> []

let arr_to_list =  function
  | `A arr ->
     List.map obj_to_alist arr
  | _ -> []

let safe_head = function
  | x :: _ -> Some x
  | _ -> None

(* let rearrange_names lists = *)
let each_alist alist =
  let open Etude.Option in
  let* name =
    List.assoc_opt "PkgName" alist >>= safe_head
  in
  let* fixed_versions =
    List.assoc_opt "FixedVersion" alist
  in
  (* let comparison x y = *)
    (* Prelude.on compare Prelude.version_of_string *)
  (* in *)
  (* pure (name, Prelude.maximumBy ~compare:comparison fixed_version) *)
  assert false

(* jq command *)
(* trivy fs --quiet --scanners vuln --format json library_website | jq '.Results[]?.Vulnerabilities | select (. != null)[] | {"PkgName" : .PkgName, "InstalledVersion" : .InstalledVersion, "FixedVersion": .FixedVersion, "Severity" : .Severity }' | jq -n '[inputs]' > cvebump/example.json *)

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
