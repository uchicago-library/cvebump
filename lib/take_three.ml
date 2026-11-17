let weaken encoding =
  let open Data_encoding in
  conv
    (fun x -> ((), x))
    (fun ((), x) -> x)
    (merge_objs unit encoding)

module FromJSON = struct
  let trivy_encoding =
    let open Data_encoding in
    weaken
      (obj2
         (req "ArtifactName" string)
         (opt "Results"
            (list
               (weaken
                  (obj2 (req "Type" string)
                     (opt "Vulnerabilities"
                        (list
                           (weaken
                              (obj5
                                 (req "PkgName" string)
                                 (req "Severity" string)
                                 (req "InstalledVersion"
                                    string )
                                 (req "FixedVersion" string)
                                 (req "References"
                                    (list string) ) ) ) ) ) ) ) ) ) )

  let parse_exn j =
    let open Data_encoding in
    Json.destruct trivy_encoding j

  let handler =
    let open Data_encoding in
    function
    | Data_encoding.Json.Cannot_destruct _ as e ->
      Format.asprintf "%a"
        (Json.print_error ?print_unknown:None)
        e
    | e -> raise e

  let parse_res j =
    Prelude.Result.trap handler parse_exn j
    |> Result.map Etude.List.pure

  let parse_array_exn j =
    let open Data_encoding in
    Json.destruct (list trivy_encoding) j

  let parse_array_res j =
    Prelude.Result.trap handler parse_array_exn j

  let parse j =
    match parse_res j with
    | Ok _ as ok -> ok
    | Error e1 -> match parse_array_res j with
                 | Ok _ as ok -> ok
                 | Error _ -> Error e1
end

let parse = FromJSON.parse
let parse_exn = FromJSON.parse_exn
let parse_array_exn = FromJSON.parse_array_exn

module CatOptions = struct
  let populated =
    function | _, [] -> false
             | _ -> true
  
  let cat_options paths =
    let open Etude.List in
    let each_path (path, platforms_opt) =
      match platforms_opt with
      | None -> []
      | Some platforms ->
         let each_platform (platform, vulns_opt) =
           match vulns_opt with
           | Some vulns -> [ (platform, vulns) ]
           | None -> []
         in
         [ (path, platforms >>= each_platform) ]
    in
    List.map each_path paths
    |> List.concat
    |> List.filter populated
end

let cat_options = CatOptions.cat_options

module CleanupRecord = struct
  let is_nist str =
    Str.(
      string_partial_match
        (regexp "^https://nvd.nist.gov")
        str 0 )

  let is_github str =
    Str.(
      string_match
        (regexp
           ".*github.com/.*/security/advisories/GHSA-.*$" )
        str 0 )

  let choose_link links =
    let nists = List.filter is_nist links in
    let githubs = List.filter is_github links in
    match (nists, githubs) with
    | [], [] -> []
    | [], _ -> githubs
    | _ -> nists

  let fix_references paths =
    let each_vuln (pkg, s, i, f, refs) =
      (pkg, s, i, f, choose_link refs)
    in
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    let each_path (path, platforms) =
      (path, List.map each_platform platforms)
    in
    List.map each_path paths

  let fix_fixed_versions paths =
    let each_vuln (pkg, s, i, f, refs) =
      (pkg, s, i, Prelude.String.split ~sep:", " f, refs)
    in
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    let each_path (path, platforms) =
      (path, List.map each_platform platforms)
    in
    List.map each_path paths
end

let fix_references = CleanupRecord.fix_references
let fix_fixed_versions = CleanupRecord.fix_fixed_versions

module Coalesce = struct
  let coalesce paths =
    let each_vuln (pkg, s, i, f, refs) =
      ((pkg, s, i), (f, refs))
    in
    let each_platform (platform, vulns) =
      let c = Prelude.List.Assoc.coalesce in
      (platform, c (List.map each_vuln vulns))
    in
    let each_path (path, platforms) =
      (path, List.map each_platform platforms)
    in
    List.map each_path paths
end

let coalesce = Coalesce.coalesce

module Comparison = struct
  let version_compare =
    Prelude.(on compare version_of_string)

  let ( ->- ) x y = version_compare x y = 1
end

let version_compare = Comparison.version_compare
let ( ->- ) = Comparison.( ->- )

module NextVersionsUp = struct
  let each_list installed (fixeds, refs) =
    let ordering x = x ->- installed in
    let filtered = List.filter ordering fixeds in
    let sorted =
      List.sort version_compare filtered
      |> Prelude.List.take 1
    in
    (String.concat "" sorted, refs)

  let each_platform (platform, vulns) =
    let each_vuln ((pkg, severity, installed), frefses) =
      ( (pkg, severity, installed),
        List.map (each_list installed) frefses )
    in
    (platform, List.map each_vuln vulns)

  let get_next_versions paths =
    let each_path (path, platforms) =
      (path, List.map each_platform platforms)
    in
    List.map each_path paths
end

let get_next_versions = NextVersionsUp.get_next_versions

module MaxVersion = struct
  let each_vuln ((pkg, severity, installed), lists) =
    let versions = List.map fst lists in
    let max =
      Prelude.maximumBy ~compare:version_compare versions
    in
    let refs = List.concat (List.map snd lists) in
    (pkg, (severity, installed, max, refs))

  let get_max_version paths =
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    let each_path (path, platforms) =
      (path, List.map each_platform platforms)
    in
    List.map each_path paths
end

let get_max_version = MaxVersion.get_max_version

module ProcessAlist = struct
  let restructure_jsons platform_jsons =
    platform_jsons
    |> cat_options
    |> fix_references
    |> fix_fixed_versions
    |> coalesce
    |> get_next_versions
    |> get_max_version
end

let restructure_jsons = ProcessAlist.restructure_jsons

module BackToJSON = struct
  let encoder =
    let open Data_encoding in
    assoc
      (assoc
         (assoc
            (obj4
               (req "severity" string)
               (req "installed-version" string)
               (req "goto" string)
               (req "references" (list string)) ) ) )

  let encode platforms =
    let open Data_encoding.Json in
    construct encoder platforms
end

let decode_many = BackToJSON.encode

let print_result = function
  | Ok json -> Json.print json
  | _ -> ()

let main () =
  match Sys.argv with
  | [|_|] ->
     let open In_channel in
     let (>>|) x f = Result.map f x in
     let json_string = input_all stdin in
     json_string
     |> Ezjsonm.from_string
     |> parse
     >>| restructure_jsons
     >>| BackToJSON.encode
     |> print_result
  | _ -> print_endline "george"

(* let str1 = Prelude.readfile "full-example.json" *)
(* let j1 = Ezjsonm.from_string str1 *)
(* let str2 = Prelude.readfile "two.json" *)
(* let j2 = Ezjsonm.from_string str2 *)
