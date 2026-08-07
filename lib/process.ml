let x = 5

let blessed_keys =
  [ "PkgName"; "InstalledVersion"; "FixedVersion" ]

let get_url urls =
  let is_cve_url url =
    let regexp =
      Str.regexp "^https://www.cve.org/CVERecord.*"
    in
    Str.string_match regexp url 0
  in
  match List.filter is_cve_url urls with
  | url :: _ -> url
  | _ -> ""

(* todo: figure out how to deal with References array to
   pull the CVE URL out *)
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

let version_compare = Prelude.(on compare version_of_string)
let ( ->- ) x y = version_compare x y = 1

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

let current_version = "5.2.12"

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

type step =
  | O of string
  | A of int

let rec find_path steps json =
  let open Etude.Option in
  match steps, json with
  | [], json -> pure json
  | O key :: stpz, `O obj ->
     let* next = List.assoc_opt key obj
     in find_path stpz next
  | A idx :: stpz , `A arr ->
     let* next = List.nth_opt arr idx
     in find_path stpz next
  | _, _ -> None

let unstring = function
  | `String s -> Some s
  | _ -> None

let unarray = function
  | `A a -> Some a
  | _ -> None

let unobject = function
  | `O o -> Some o
  | _ -> None

(* let each_platform json =
 *   let open Etude.Option in
 *   let+ typ = find_path [O "Type"] json >>= unstring
 *   and+ packages = find_path [O "Packages"] json in
 *   (typ, packages) *)

let trivy_output_to_vulns json =
  let open Etude.Option in
  let* results = find_path [ O "Results" ] json >>= unarray in
  let each_result json = find_path [ O "Vulnerabilities" ] json in
  traverse each_result results
  >>= traverse unarray
  >>= traverse (traverse unobject)
  >>| List.flatten


(* jq command *)
(* trivy fs --quiet --scanners vuln --format json library_website | jq '.Results[]?.Vulnerabilities | select (. != null)[] | {"PkgName" : .PkgName, "InstalledVersion" : .InstalledVersion, "FixedVersion": .FixedVersion, "Severity" : .Severity }' | jq -n '[inputs]' > cvebump/example.json *)

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
