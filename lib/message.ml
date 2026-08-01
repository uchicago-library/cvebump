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

let version_compare = Prelude.(on compare version_of_string)
let ( ->- ) x y = version_compare x y = 1

(* let rearrange_names lists = *)
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
  let each_pair ((name, current), versions) =
    name, current, get_version current versions
  in
  coalesce_lists lists
  |> Option.get
  |> List.map each_pair

(* # coalesce_lists lists |> Option.get |> List.map (fun ((name, current), versions) -> (name, current, get_version current versions));;
 * - : (string * string * string Etude.Option.t) list =
 * [("yaml", "1.10.2", Etude.Option.Some "1.10.3");
 *  ("wagtail", "7.0.6", Etude.Option.Some "7.0.7");
 *  ("urllib3", "2.6.3", Etude.Option.Some "2.7.0");
 *  ("serialize-javascript", "7.0.4", Etude.Option.Some "7.0.5");
 *  ("picomatch", "2.3.1", Etude.Option.Some "2.3.2");
 *  ("lodash", "4.17.23", Etude.Option.Some "4.18.0");
 *  ("js-yaml", "4.1.1", Etude.Option.Some "4.3.0");
 *  ("flatted", "3.3.3", Etude.Option.Some "3.4.2");
 *  ("brace-expansion", "1.1.12", Etude.Option.Some "1.1.17");
 *  ("bleach", "3.3.0", Etude.Option.Some "6.4.0");
 *  ("Pygments", "2.15.0", Etude.Option.Some "2.20.0");
 *  ("Django", "5.2.12", Etude.Option.Some "5.2.15");
 *  ("@babel/core", "7.29.0", Etude.Option.Some "7.29.6")] *)

(* let coalesce_lists lists =
 *   let open Etude.Option in
 *   let+ traversed = traverse each_alist in
 *   coalesce traversed *)

(* jq command *)
(* trivy fs --quiet --scanners vuln --format json library_website | jq '.Results[]?.Vulnerabilities | select (. != null)[] | {"PkgName" : .PkgName, "InstalledVersion" : .InstalledVersion, "FixedVersion": .FixedVersion, "Severity" : .Severity }' | jq -n '[inputs]' > cvebump/example.json *)

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
