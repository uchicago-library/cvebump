let x = 5

let blessed_keys =
  [ "PkgName"; "InstalledVersion"; "FixedVersion"; "References"; ]

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

let blessed (k, _) = List.mem k blessed_keys

let trivy_output_to_platforms json =
  let open Etude.Option in
  let* results = find_path [ O "Results" ] json >>= unarray in
  let each_result json =
    let+ vulns =
      find_path [ O "Vulnerabilities" ] json >>= unarray
      >>= traverse unobject
    and+ target = find_path [ O "Type" ] json >>= unstring in
    let filtered = List.map (List.filter blessed) vulns in
    (target, filtered)
  in
  let* platforms =
    traverse each_result results
  in
  pure platforms

let is_nist str =
  Str.(string_partial_match (regexp "^https://nvd.nist.gov") str 0)

let platforms_to_alist platforms =
  let open Etude.Option in
  let stringify = function
    | (x, `A arr) ->
       let* references = traverse unstring arr in
       let filtered = List.filter is_nist references in
       pure (x, filtered)
    | (x, `String s) ->
       let* str = unstring (`String s)
       in pure (x, [str])
    | _ -> None
  in
  let each_platform (platform, data) =
    let+ processed = traverse (traverse stringify) data in
    (platform, processed)
  in
  traverse each_platform platforms

let not_coalesced json =
  let open Etude.Option in
  json
  |> (trivy_output_to_platforms >=> platforms_to_alist)

let alerts =
  let json =
    Prelude.readfile "./full-example.json"
    |> Ezjsonm.from_string
  in
  not_coalesced json
  |> Option.get
  |> List.hd
  |> snd
  |> Prelude.take 15

let each_alert alert =
  let open Etude.Option in
  let* pkgname = List.assoc_opt "PkgName" alert >>= safe_head in
  let new_assocs = List.remove_assoc "PkgName" alert in
  pure (pkgname, new_assocs)

let process_alerts alerts =
  let open Etude.Option in
  let+ pkgname_in_front =
    traverse each_alert alerts
  in
  Prelude.List.Assoc.coalesce pkgname_in_front

(* jq command *)
(* trivy fs --quiet --scanners vuln --format json library_website | jq '.Results[]?.Vulnerabilities | select (. != null)[] | {"PkgName" : .PkgName, "InstalledVersion" : .InstalledVersion, "FixedVersion": .FixedVersion, "Severity" : .Severity }' | jq -n '[inputs]' > cvebump/example.json *)

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
