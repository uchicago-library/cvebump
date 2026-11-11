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

  let stub_encoding =
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

  let parse_ j =
    let open Data_encoding in
    Json.destruct stub_encoding j

  let parse enc j =
    let open Data_encoding in
    Json.destruct enc j
end



(* module CoalescedByPkg = struct *)
(*   type t = string * FromJSON.t *)
(*   let to_alist = function *)
(*     | { FromJSON.package_name ; _ } as fj -> package_name, fj *)
(*   let coalesce fromjsons = *)
(*     let keys_added = List.map to_alist fromjsons in *)
(*     Prelude.List.Assoc.coalesce keys_added *)
(* end *)

(* module CoalescedByPackage = struct *)
(*   type vuln_info = { installed_version : string list ; *)
(*                      fixed_version : string list ; *)
(*                      references : string list ; *)
(*                      platform_name : string ; } *)
(*   type package = string *)
(*   type t = package * vuln_info list *)
(* end *)

