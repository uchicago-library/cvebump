let x = 5

let blessed_keys =
  [ "PkgName"; "InstalledVersion"; "FixedVersion"; "InstalledVersion"; "References"; ]

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

let is_github str =
  Str.(string_match (regexp ".*GHSA-.*$") str 0)

let platforms_to_alist platforms =
  let open Etude.Option in
  let stringify = function
    | (x, `A arr) ->
       let* references = traverse unstring arr in
       let filtered =
         let nists = List.filter is_nist references in
         let githubs = List.filter is_github references in
         match nists, githubs, references with
         | [], [], [] -> []
         | [], [], _ -> references
         | [], _, _ -> githubs
         | _ -> nists
       in 
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

let each_alert alert =
  let open Etude.Option in
  let* pkgname = List.assoc_opt "PkgName" alert >>= safe_head in
  let new_assocs = List.remove_assoc "PkgName" alert in
  pure (pkgname, new_assocs)

let process_json json =
  let open Etude.Option in
  let* nc = not_coalesced json in
  let each_platform (platform, alrtz) =
    let+ alerts = traverse each_alert alrtz in
    (platform, alerts)
  in
  traverse each_platform nc

let each_assocs assocs =
  let open Etude.Option in
  let conc s = String.concat "" s in
  let split s = Prelude.split ~sep:", " s
                |> List.map String.trim
  in
  let+ versions_str = List.assoc_opt "FixedVersion" assocs 
  and+ current = List.assoc_opt "InstalledVersion" assocs 
  and+ references = List.assoc_opt "References" assocs
  in
  conc current, split (conc versions_str), references

let each_version_triple (curr, fixed_versions, _) =
  let ordering x = x ->- curr in
  List.filter ordering (List.sort version_compare fixed_versions) |> safe_head

let get_optimal_version version_triples =
  let open Etude.Option in
  let versions trips =
    traverse each_version_triple trips
  in
  let+ vs = versions version_triples in
  Prelude.maximumBy ~compare:version_compare vs

let process_triples triples =
  let open Etude.Option in
  let refs =
    let each_triple (_,_,r) = r in
    List.map each_triple triples
  in
  let+ optimal_version = get_optimal_version triples in
  (optimal_version, List.concat refs)

(* convert trivy output to alist *)
let trivy_output_to_alist = process_json

(* for debugging: just coalesces *)
let trivy_to_coalesced_alist json =
  let open Etude.Option in
  let+ uncoalesced = process_json json in
  let each_platform (name, packages) =
    (name, Prelude.List.Assoc.coalesce packages)
  in
  List.map each_platform uncoalesced

(* helper function for traversing into each package *)
let traverse_inside_packages f alist =
  let open Etude.Option in
  let each_platform (pltfrm, pkgs) =
    let each_package (pkg, vulns) =
      let+ vs = f vulns in
      (pkg, vs)
    in
    let+ ps = traverse each_package pkgs
    in (pltfrm, ps)
  in
  traverse each_platform alist

(* for debugging: just converts each vulnerability alist into
   triples *)
let coalesced_to_triples alist =
  let open Etude.Option in
  traverse_inside_packages (traverse each_assocs) alist

(* converts each list of triples into a recommended version *)
let coalesced_to_versions alist =
  let open Etude.Option in
  traverse_inside_packages
    (traverse each_assocs >=> process_triples)
    alist

(* converts trivy output to my output *)
let trivy_to_output json =
  let open Etude.Option in
  trivy_to_coalesced_alist json >>= coalesced_to_versions

(* TESTING *)

let json =
  Prelude.readfile "./full-example.json"
  |> Ezjsonm.from_string

let shorten_for_testing n alist =
  let each_platform (pltfrm, pkgs) =
    let each_package (pkg, vulns) =
      (pkg, Prelude.List.take n vulns)
    in
    (pltfrm, Prelude.List.take n (List.map each_package pkgs))
  in List.map each_platform alist
  
let test_json =
  json
  |> trivy_to_coalesced_alist
  |> Option.value ~default:[]
  |> shorten_for_testing 3

let alerts =
  not_coalesced json
  |> Option.get
  |> List.hd
  |> snd
  |> Prelude.take 15
