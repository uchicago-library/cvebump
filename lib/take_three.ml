let weaken encoding =
  let open Data_encoding in
  conv (fun x -> ((), x)) (fun ((), x) -> x) (merge_objs unit encoding)

(* the first datatype we parse the Trivy JSON into *)
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
                     (req "Vulnerabilities"
                        (list
                           (weaken
                              (obj4
                                 (req "PkgName" string)
                                 (req "InstalledVersion" string)
                                 (req "FixedVersion" string)
                                 (req "References" (list string)))))))))))

  let parse_ enc j =
    let open Data_encoding in
    Json.destruct enc j

  let parse j = parse_ trivy_encoding j
end

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

let version_compare = Prelude.(on compare version_of_string)
let ( ->- ) x y = version_compare x y = 1

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

module MaxVersion = struct
  let each_vuln ((pkg, installed), lists) =
    let versions = List.map fst lists in
    let max = Prelude.maximumBy ~compare:version_compare versions in
    let refs = List.concat (List.map snd lists) in
    (pkg, installed, max, refs)

  let get_max_version platforms =
    let each_platform (platform, vulns) =
      (platform, List.map each_vuln vulns)
    in
    List.map each_platform platforms
end

module ProcessAlist = struct
  let restructure_alist platforms =
    platforms
    |> CleanupRecord.fix_references
    |> CleanupRecord.fix_fixed_versions
    |> Coalesce.coalesce
    |> NextVersionsUp.get_next_versions
    |> MaxVersion.get_max_version
end

let j = Process.(json path)

let parse = FromJSON.parse

let restructure_alist = ProcessAlist.restructure_alist

module BackToJSON = struct
  
end
