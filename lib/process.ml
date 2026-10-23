let version_compare = Prelude.(on compare version_of_string)
let ( ->- ) x y = version_compare x y = 1

let safe_head = function
  | x :: _ -> Some x
  | _ -> None

let blessed_keys =
  [ "PkgName"; "InstalledVersion"; "FixedVersion"; "References"; ]

let blessed (k, _) = List.mem k blessed_keys

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
  Str.(string_match (regexp ".*github.com/advisories.*GHSA-.*$") str 0)

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

(* get the next highest version up from the current version *)
let each_version_triple (curr, fixed_versions, _) =
  let ordering x = x ->- curr in
  List.filter ordering (List.sort version_compare fixed_versions) |> safe_head

(* take list of triples to optimal version number *)
let get_optimal_version version_triples =
  let open Etude.Option in
  let versions trips =
    traverse each_version_triple trips
  in
  let+ vs = versions version_triples in
  Prelude.maximumBy ~compare:version_compare vs

(* compute optimal version & gather references into a list *)
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

let back_to_json alist =
  let string s = `String s in
  let each_vuln (vname, (version, links)) =
    (vname, `O [ ("UpgradeTo", `String version);
                 ("References", `A (List.map string links))])
  in
  let each_platform (pname, pvulns) =
    (pname, `O (List.map each_vuln pvulns))
  in
  `O (List.map each_platform alist)
  

(* TESTING *)

let path = "./fresh-example.json"

let json path =
  Prelude.readfile path
  |> Ezjsonm.from_string 

let shorten_for_testing n alist =
  let each_platform (pltfrm, pkgs) =
    let each_package (pkg, vulns) =
      (pkg, Prelude.List.take n vulns)
    in
    (pltfrm, Prelude.List.take n (List.map each_package pkgs))
  in List.map each_platform alist
  
let test_json () =
  (json path)
  |> trivy_to_coalesced_alist
  |> Option.value ~default:[]
  |> shorten_for_testing 3

let alerts () =
  not_coalesced (json path)
  |> Option.get
  |> List.hd
  |> snd
  |> Prelude.take 15
