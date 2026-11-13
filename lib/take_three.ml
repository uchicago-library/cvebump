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
      (obj1
         (req "Results"
            (list
               (weaken
                  (obj2
                     (req "Type" string)
                     (opt "Vulnerabilities"
                        (list
                           (weaken
                              (obj4
                                 (req "PkgName" string)
                                 (req "InstalledVersion" string)
                                 (req "FixedVersion" string)
                                 (req "References" (list string)))))))))))

  let parse j =
    let open Data_encoding in
    Json.destruct trivy_encoding j
end

let parse = FromJSON.parse

module CatOptions = struct
  let cat_options platforms =
    let each_platform (platform, vulns_opt) =
      match vulns_opt with
      | Some vulns -> [(platform, vulns)]
      | None -> []
    in
    Etude.List.bind platforms each_platform
end

let cat_options = CatOptions.cat_options

module CleanupRecord = struct
  let is_nist str =
    Str.(string_partial_match (regexp "^https://nvd.nist.gov") str 0)

  let is_github str =
    Str.(string_match (regexp ".*github.com/.*/security/advisories/GHSA-.*$") str 0)

  let choose_link links =
    let nists = List.filter is_nist links in
    let githubs = List.filter is_github links in
    match nists, githubs with
    | [], [] -> []
    | [], _ -> githubs
    | _ -> nists

  let fix_references platforms =
    let each_vuln (pkg, i, f, refs) =
      (pkg, i, f, choose_link refs)
    in
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    List.map each_platform platforms

  let fix_fixed_versions platforms =
    let each_vuln (pkg, i, f, refs) =
      (pkg, i, Prelude.String.split ~sep:", " f, refs)
    in
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    List.map each_platform platforms
end

let fix_references = CleanupRecord.fix_references
let fix_fixed_versions = CleanupRecord.fix_fixed_versions

module Coalesce = struct
  let coalesce platforms =
    let each_vuln (pkg, i, f, refs) =
      (pkg, i), (f, refs)
    in
    let each_platform (platform, vulns) =
      let c = Prelude.List.Assoc.coalesce in
      (platform, c (List.map each_vuln vulns))
    in
    List.map each_platform platforms
end

let coalesce = Coalesce.coalesce

module Comparison = struct
  let version_compare = Prelude.(on compare version_of_string)
  let ( ->- ) x y = version_compare x y = 1
end

let version_compare = Comparison.version_compare
let ( ->- ) = Comparison.( ->- )

module NextVersionsUp = struct
  let each_list installed (fixeds, refs) = 
    let ordering x = x ->- installed in
    let filtered = List.filter ordering fixeds in
    let sorted = List.sort version_compare filtered in
    (String.concat "" sorted, refs)

  let each_platform (platform, vulns) =
    let each_vuln ((pkg, installed), frefses) =
      ((pkg, installed), List.map (each_list installed) frefses)
    in
    (platform, List.map each_vuln vulns)

  let get_next_versions platforms =
    List.map each_platform platforms
end

let get_next_versions = NextVersionsUp.get_next_versions

module MaxVersion = struct
  let each_vuln ((pkg, installed), lists) =
    let versions = List.map fst lists in
    let max = Prelude.maximumBy ~compare:version_compare versions in
    let refs = List.concat (List.map snd lists) in
    pkg, (installed, max, refs)

  let get_max_version platforms =
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    List.map each_platform platforms
end

let get_max_version = MaxVersion.get_max_version

module ProcessAlist = struct
  let restructure_alist platforms =
    platforms
    |> cat_options
    |> fix_references
    |> fix_fixed_versions
    |> coalesce
    |> get_next_versions
    |> get_max_version
end

let restructure_alist = ProcessAlist.restructure_alist

module BackToJSON = struct
  let enc =
    let open Data_encoding in
    assoc
      (assoc
         (obj3
            (req "installed-version" string)
            (req "goto" string)
            (req "references" (list string))))

  let serialize platforms =
    let open Data_encoding.Json in
    construct enc platforms
end

let serialize = BackToJSON.serialize

let main () =
  match Sys.argv with
  | [|_|] -> (let open In_channel in
             let json_string = input_all stdin in
             let json = Ezjsonm.from_string json_string in
             let parsed = parse json in
             parsed
             |> restructure_alist
             |> serialize
             |> Json.print)
  | _ -> print_endline "george"
