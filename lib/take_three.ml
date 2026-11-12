let weaken encoding =
  let open Data_encoding in
  conv (fun x -> ((), x)) (fun ((), x) -> x) (merge_objs unit encoding)

(* the first datatype we parse the Trivy JSON into *)
module FromJSON = struct
  type t = { package_name : string ;
             installed_version : string list ;
             fixed_version : string list ;
             references : string list ;
             platform_name : string ; }
  let make
        package_name
        installed_version
        fixed_version
        references
        platform_name =
    { package_name ;
      installed_version ;
      fixed_version ;
      references ;
      platform_name }

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

module ComputeVersion = struct
  let coalesce platforms =
    let each_vuln (pkg, i, f, refs) =
      pkg, (i, f, refs)
    in
    let each_platform (platform, vulns) =
      let c = Prelude.List.Assoc.coalesce in
      (platform, c (List.map each_vuln vulns))
    in
    List.map each_platform platforms
end
