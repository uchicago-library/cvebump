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
    List.assoc_opt "InstalledVersion" alist
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

(* # coalesce_lists lists |> Option.get |> List.map (fun ((name, current), versions) -> (name, get_version (List.hd current) versions));;
 * - : (string * string Etude.Option.t) list =
 * [("yaml", Etude.Option.Some "1.10.3");
 *  ("wagtail", Etude.Option.Some "7.0.7");
 *  ("urllib3", Etude.Option.Some "2.7.0");
 *  ("serialize-javascript", Etude.Option.Some "7.0.5");
 *  ("picomatch", Etude.Option.Some "2.3.2");
 *  ("lodash", Etude.Option.Some "4.18.0");
 *  ("js-yaml", Etude.Option.Some "4.3.0");
 *  ("flatted", Etude.Option.Some "3.4.2");
 *  ("brace-expansion", Etude.Option.Some "1.1.17");
 *  ("bleach", Etude.Option.Some "6.4.0");
 *  ("Pygments", Etude.Option.Some "2.20.0");
 *  ("Django", Etude.Option.Some "5.2.15");
 *  ("@babel/core", Etude.Option.Some "7.29.6")] *)

(* let coalesce_lists lists =
 *   let open Etude.Option in
 *   let+ traversed = traverse each_alist in
 *   coalesce traversed *)

(* jq command *)
(* trivy fs --quiet --scanners vuln --format json library_website | jq '.Results[]?.Vulnerabilities | select (. != null)[] | {"PkgName" : .PkgName, "InstalledVersion" : .InstalledVersion, "FixedVersion": .FixedVersion, "Severity" : .Severity }' | jq -n '[inputs]' > cvebump/example.json *)

(* Local Variables: *)
(* mode: tuareg *)
(* End: *)
