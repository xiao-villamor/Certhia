use crate::auth::{Access, Role, classify};
use axum::Json;
use serde_json::{Value, json};

pub fn document() -> Value {
    let mut endpoints = serde_json::Map::new();
    for (path, method, section, summary) in [
        (
            "/auth/status",
            "get",
            "Authentication",
            "List sign-in methods and first-run status",
        ),
        (
            "/auth/setup",
            "post",
            "Authentication",
            "Create the first administrator using the setup code",
        ),
        (
            "/auth/login",
            "post",
            "Authentication",
            "Sign in with a local account",
        ),
        (
            "/auth/me",
            "get",
            "Authentication",
            "Read the current session and account",
        ),
        (
            "/auth/logout",
            "post",
            "Authentication",
            "End the current session",
        ),
        (
            "/auth/password",
            "put",
            "Authentication",
            "Change your local password and revoke your sessions",
        ),
        (
            "/auth/oidc/{provider}/start",
            "post",
            "Authentication",
            "Start an OpenID Connect sign-in",
        ),
        (
            "/auth/oidc/{provider}/callback",
            "get",
            "Authentication",
            "Complete an OpenID Connect sign-in",
        ),
        ("/settings/sso", "get", "Authentication", "Read workspace single sign-on settings and redirect URI"),
        ("/settings/sso", "put", "Authentication", "Save workspace single sign-on settings"),
        ("/users", "get", "Users", "List workspace users"),
        ("/users", "post", "Users", "Create a workspace user"),
        (
            "/users/{id}",
            "put",
            "Users",
            "Update a user's display name, role or enabled status",
        ),
        (
            "/users/{id}/sessions/revoke",
            "post",
            "Users",
            "Revoke all sessions for a user",
        ),
        (
            "/openapi.json",
            "get",
            "System",
            "Read the OpenAPI description",
        ),
        (
            "/config/raw-output",
            "get",
            "System",
            "Read raw scanner artifact configuration",
        ),
        ("/health", "get", "System", "Check process liveness"),
        (
            "/dashboard",
            "get",
            "Library",
            "Read scan totals and digest severity counts",
        ),
        (
            "/library/top-packages",
            "get",
            "Library",
            "Rank packages by open findings",
        ),
        (
            "/library/advisories",
            "get",
            "Library",
            "Search advisory IDs and affected image counts",
        ),
        (
            "/library/advisories/{id}/digests",
            "get",
            "Library",
            "List open affected manifests",
        ),
        (
            "/advisories/{id}",
            "get",
            "Library",
            "Read advisory description, scores and references",
        ),
        (
            "/repositories/{id}/findings",
            "get",
            "Library",
            "List open findings for a repository",
        ),
        (
            "/digests/{a}/compare/{b}",
            "get",
            "Library",
            "Compare open findings on two manifests",
        ),
        ("/ready", "get", "System", "Check readiness"),
        ("/version", "get", "System", "Read the application version"),
        (
            "/settings",
            "get",
            "System",
            "Read retention and notification settings",
        ),
        (
            "/settings",
            "put",
            "System",
            "Save retention and notification settings",
        ),
        (
            "/settings/report-branding",
            "get",
            "Reports",
            "Read report branding and the latest completed scan ID",
        ),
        (
            "/settings/report-branding",
            "put",
            "Reports",
            "Save the organization name and report footer",
        ),
        (
            "/settings/report-branding/logo",
            "get",
            "Reports",
            "Download the current report logo",
        ),
        (
            "/settings/report-branding/logo",
            "put",
            "Reports",
            "Upload a PNG or JPEG report logo up to 1 MB",
        ),
        (
            "/settings/report-branding/logo",
            "delete",
            "Reports",
            "Remove the current report logo",
        ),
        (
            "/settings/notifications/test",
            "post",
            "System",
            "Send a test notification",
        ),
        (
            "/image-watches",
            "get",
            "Scheduling",
            "List watched images and recent vulnerability alerts",
        ),
        (
            "/image-watches/{id}",
            "delete",
            "Scheduling",
            "Stop watching an image",
        ),
        (
            "/scans/{id}/watch",
            "get",
            "Scans",
            "Read the watch for a scan's reference and platform",
        ),
        (
            "/scans/{id}/watch",
            "put",
            "Scans",
            "Watch an image for newly detected vulnerabilities",
        ),
        (
            "/settings/scanners",
            "put",
            "Scans",
            "Save the workspace scanner providers",
        ),
        (
            "/settings/issue-trackers",
            "get",
            "Settings",
            "List the configured issue trackers",
        ),
        (
            "/settings/issue-trackers",
            "post",
            "Settings",
            "Add an issue tracker",
        ),
        (
            "/settings/issue-trackers/{id}",
            "put",
            "Settings",
            "Update an issue tracker",
        ),
        (
            "/settings/issue-trackers/{id}",
            "delete",
            "Settings",
            "Remove an issue tracker",
        ),
        ("/audit-logs", "get", "System", "Read recent audit events"),
        (
            "/scanners/available",
            "get",
            "Scans",
            "List available scanner engines",
        ),
        ("/scans", "get", "Scans", "List recent scans"),
        ("/scans", "post", "Scans", "Queue an image scan"),
        ("/scans/{id}", "get", "Scans", "Read a scan and its report"),
        (
            "/scans/{id}/retry-options",
            "get",
            "Scans",
            "Read the original scan inputs for an editable retry",
        ),
        (
            "/scans/{id}/rescan",
            "post",
            "Scans",
            "Queue a new scan for the image",
        ),
        (
            "/scans/{id}/cancel",
            "post",
            "Scans",
            "Cancel a queued or running scan",
        ),
        (
            "/scans/{id}/progress",
            "get",
            "Scans",
            "Read current progress and queue position",
        ),
        (
            "/scans/{id}/events",
            "get",
            "Scans",
            "Subscribe to scan progress",
        ),
        (
            "/scans/{id}/report/{format}",
            "get",
            "Scans",
            "Download a report as PDF, XLSX, Markdown, JSON, raw, CycloneDX SBOM, SPDX 2.3 JSON, CycloneDX CBOM, OpenVEX, or ZIP",
        ),
        (
            "/scans/{id}/report/summary",
            "get",
            "Scans",
            "Read report metadata and finding totals by ecosystem and severity",
        ),
        (
            "/scans/{id}/report/findings",
            "get",
            "Scans",
            "Page through vulnerability findings with aliases, scanners, and tracking status",
        ),
        (
            "/scans/{id}/report/scanner-differences",
            "get",
            "Scans",
            "Page through scanner differences and read comparison totals on the first page",
        ),
        (
            "/scans/{id}/scanner-results",
            "get",
            "Scans",
            "List raw scanner artifacts",
        ),
        (
            "/scans/{id}/finding-sources",
            "get",
            "Scans",
            "List recorded scanner detections by finding",
        ),
        (
            "/scans/{id}/scanner-results/{tool}",
            "get",
            "Scans",
            "Download a scanner artifact or a retained scheduled SBOM (scheduled-sbom)",
        ),
        (
            "/scans/{id}/classifications",
            "get",
            "Scans",
            "List finding statuses, notes, and linked issues",
        ),
        (
            "/scans/{id}/classifications",
            "put",
            "Scans",
            "Update a finding status, note, and linked issue",
        ),
        (
            "/scans/bulk",
            "post",
            "Scans",
            "Queue a batch of image scans",
        ),
        ("/scans/bulk", "get", "Scans", "List batch history"),
        (
            "/scans/import",
            "post",
            "Scans",
            "Import a Trivy JSON report",
        ),
        (
            "/scans/archive",
            "post",
            "Scans",
            "Upload an image archive and queue a scan",
        ),
        (
            "/compare",
            "get",
            "Images",
            "Compare package inventories and vulnerability observations from shared scanners",
        ),
        (
            "/scans/{id}/previous",
            "get",
            "Scans",
            "Find the previous completed scan for the same image reference and platform",
        ),
        (
            "/scans/{id}/previous-version",
            "get",
            "Scans",
            "Suggest an earlier report in the same repository and platform",
        ),
        (
            "/compare/plan",
            "post",
            "Images",
            "Resolve image references and queue missing scans",
        ),
        ("/images", "get", "Images", "List image histories"),
        (
            "/images/delete",
            "post",
            "Images",
            "Delete selected scan histories",
        ),
        (
            "/images/{id}/archive",
            "get",
            "Images",
            "Download the image as an archive",
        ),
        (
            "/images/{id}/publish",
            "post",
            "Images",
            "Copy an image to a destination registry",
        ),
        (
            "/images/{id}/layers",
            "get",
            "Images",
            "Inspect image layer sizes and digests",
        ),
        (
            "/images/{id}/layers/{index}/files",
            "get",
            "Images",
            "List files changed by an image layer",
        ),
        (
            "/vulnerabilities",
            "get",
            "Images",
            "Read the vulnerability library",
        ),
        (
            "/library/packages",
            "get",
            "Images",
            "Aggregate advisory severity by package",
        ),
        ("/registries", "get", "Registries", "List saved connections"),
        (
            "/registries",
            "post",
            "Registries",
            "Save a registry connection",
        ),
        (
            "/registries/{id}",
            "put",
            "Registries",
            "Update a registry connection",
        ),
        (
            "/registries/{id}",
            "delete",
            "Registries",
            "Remove a registry connection",
        ),
        (
            "/registries/test",
            "post",
            "Registries",
            "Test pull access to an image",
        ),
        (
            "/registries/{id}/catalog",
            "get",
            "Registries",
            "Read a cached repository catalog",
        ),
        (
            "/registries/{id}/catalog",
            "post",
            "Registries",
            "Refresh a repository catalog",
        ),
        (
            "/registries/{id}/test",
            "post",
            "Registries",
            "Test saved credentials on an exact image reference",
        ),
        (
            "/registries/{id}/tags",
            "get",
            "Registries",
            "List tags within a repository",
        ),
        (
            "/discover/dockerhub",
            "get",
            "Discovery",
            "Search Docker Hub",
        ),
        (
            "/discover/docker",
            "get",
            "Discovery",
            "Discover images in the configured Docker Engine",
        ),
        (
            "/discover/swarm",
            "get",
            "Discovery",
            "Discover images in Docker Swarm services",
        ),
        (
            "/discover/kubernetes/namespaces",
            "get",
            "Discovery",
            "List Kubernetes namespaces",
        ),
        (
            "/discover/kubernetes",
            "get",
            "Discovery",
            "Discover images in Kubernetes pods",
        ),
        (
            "/discover/dockerhub/tags",
            "get",
            "Discovery",
            "List tags for a public Docker Hub repository",
        ),
        ("/scheduled-scans", "get", "Scheduling", "List schedules"),
        (
            "/scheduled-scans/preview",
            "get",
            "Scheduling",
            "Validate a cron expression and preview its next run",
        ),
        (
            "/scheduled-scans/kubernetes",
            "get",
            "Scheduling",
            "Test Kubernetes pod access for a schedule",
        ),
        (
            "/registries/{id}/webhook",
            "get",
            "Webhooks",
            "Read registry webhook setup",
        ),
        (
            "/registries/{id}/webhook",
            "post",
            "Webhooks",
            "Generate or rotate the registry webhook token",
        ),
        (
            "/registries/{id}/webhook",
            "delete",
            "Webhooks",
            "Revoke the registry webhook token",
        ),
        (
            "/webhooks/registries/{id}/ci",
            "post",
            "Webhooks",
            "Queue a registry scan from CI",
        ),
        (
            "/webhooks/registries/{id}/ci/{scan_id}",
            "get",
            "Webhooks",
            "Read a CI scan result for this registry",
        ),
        (
            "/webhooks/registries/{id}/harbor",
            "post",
            "Webhooks",
            "Queue scans from a Harbor push",
        ),
        (
            "/scheduled-scans",
            "post",
            "Scheduling",
            "Create a schedule for image references, tags, or Kubernetes digest changes",
        ),
        (
            "/scheduled-scans/{id}",
            "put",
            "Scheduling",
            "Update or toggle a schedule",
        ),
        (
            "/scheduled-scans/{id}",
            "delete",
            "Scheduling",
            "Delete a schedule",
        ),
        (
            "/scheduled-scans/{id}/execute",
            "post",
            "Scheduling",
            "Run a schedule now",
        ),
        (
            "/scheduled-scans/history",
            "get",
            "Scheduling",
            "List schedule run history",
        ),
        (
            "/patches/analyze/{id}",
            "get",
            "Patches",
            "List available OS package updates",
        ),
        (
            "/patches/execute",
            "post",
            "Patches",
            "Save a dry run or build a patched image",
        ),
        ("/patches/history", "get", "Patches", "List patch history"),
        (
            "/patches/{id}/status",
            "get",
            "Patches",
            "Read patch status",
        ),
        (
            "/patches/{id}/download",
            "get",
            "Patches",
            "Download a patched OCI archive",
        ),
        (
            "/patches/{id}/publish",
            "post",
            "Patches",
            "Publish a patched image and record its manifest digest",
        ),
        (
            "/patch-publications/{id}/scan",
            "post",
            "Patches",
            "Queue a scan of the published manifest",
        ),
    ] {
        let mut parameters = path
            .split('/')
            .filter_map(|part| part.strip_prefix('{')?.strip_suffix('}'))
            .map(|name| json!({"name":name,"in":"path","required":true,"schema":{"type":"string"}}))
            .collect::<Vec<_>>();
        let query = match path {
            "/users" if method == "get" => &["limit", "cursor"][..],
            "/auth/oidc/{provider}/callback" => &["state", "code", "iss", "error"][..],
            "/registries" if method == "get" => &["search", "limit", "cursor"][..],
            "/registries/{id}/catalog" => &["search", "limit", "cursor"][..],
            "/scans" if method == "get" => {
                &["q", "status", "repository", "platform", "limit", "cursor"][..]
            }
            "/images" => &["q", "status", "repository", "platform", "limit", "cursor"][..],
            "/scans/{id}/classifications" if method == "get" => &["finding", "limit", "cursor"][..],
            "/scans/{id}/report/findings" => &["q", "advisory", "severity", "status", "groups", "collapsed", "limit", "cursor"],
            "/scans/{id}/report/scanner-differences" => &["q", "status", "limit", "cursor"],
            "/compare" => &["baseline", "target", "publication"][..],
            "/scans/import" => &["reference", "platform"][..],
            "/scans/archive" => &["reference", "platform", "scanners", "priority"][..],
            "/vulnerabilities" => &[
                "q",
                "package",
                "advisory",
                "severity",
                "status",
                "linked",
                "ecosystems",
                "fixable",
                "latest",
                "limit",
                "cursor",
            ][..],
            "/discover/dockerhub" => &["q"][..],
            "/registries/{id}/tags" | "/discover/dockerhub/tags" => &["image"][..],
            "/discover/kubernetes" => &["namespace"][..],
            "/scheduled-scans/kubernetes" => &["namespace"][..],
            "/scheduled-scans/preview" => &["expression"][..],
            _ => &[],
        };
        parameters.extend(query.iter().map(|name| {
            let required = matches!(
                (path, *name),
                ("/auth/oidc/{provider}/callback", "state")
                    | ("/compare", "baseline" | "target")
                    | ("/scans/import" | "/scans/archive", "reference" | "platform")
                    | ("/discover/dockerhub", "q")
                    | ("/scheduled-scans/preview", "expression")
                    | (
                        "/registries/{id}/tags" | "/discover/dockerhub/tags",
                        "image"
                    )
            );
            let kind = match *name {
                "limit" => "integer",
                "fixable" | "latest" | "linked" => "boolean",
                _ => "string",
            };
            json!({"name":name,"in":"query","required":required,"schema":{"type":kind}})
        }));
        let mut operation = json!({"summary":summary,"tags":[section],"parameters":parameters,
            "responses":{"2XX":{"description":"Success"},"default":{"description":"Error response"}}});
        let access = classify(&method.to_ascii_uppercase(), path)
            .expect("Each API operation has an access policy");
        if let Access::Session(role) = access {
            operation["security"] = json!([{"SessionCookie":[]},{"LocalSessionCookie":[]}]);
            operation["x-required-role"] = json!(role);
            operation["responses"]["401"] =
                json!({"description":"Missing, expired, or revoked session"});
            operation["responses"]["403"] =
                json!({"description":"Insufficient role or rejected request origin"});
        }
        if ["post", "put"].contains(&method) && path != "/scans/{id}/watch" {
            let content = if path == "/scans/archive" {
                "application/x-tar"
            } else {
                "application/json"
            };
            operation["requestBody"] = json!({"content":{content:{"schema":{"type":if content=="application/json" {"object"} else {"string"}}}}});
        }
        match path {
            "/scans/{id}/classifications" if method == "put" => {
                operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                    "type":"object", "required":["finding","status"],
                    "properties":{
                        "finding":{"type":"string","maxLength":150},
                        "status":{"type":"string","enum":crate::operations::FINDING_STATUSES},
                        "note":{"type":"string","maxLength":4000},
                        "exceptionEdit":{"description":"Set or revoke an exception for this advisory and platform. Omit to keep existing exceptions.",
                            "oneOf":[
                                {"type":"object","required":["action","scope","reason","expiresAt"],"properties":{
                                    "action":{"const":"set"},"scope":{"enum":["reference","repository"]},
                                    "reason":{"type":"string","minLength":1,"maxLength":4000},
                                    "expiresAt":{"type":"string","format":"date-time"}
                                }},
                                {"type":"object","required":["action","scope"],"properties":{
                                    "action":{"const":"revoke"},"scope":{"enum":["reference","repository"]}
                                }}
                            ]},
                        "issue":{"description":"Omit to keep the current issue link. Use null to remove it.",
                            "oneOf":[{"type":"null"},{"type":"object","required":["trackerId","key"],"properties":{
                                "trackerId":{"type":"string","format":"uuid"},
                                "key":{"type":"string","maxLength":100}
                            }}]}
                    }
                }}}});
            }
            "/settings/issue-trackers" | "/settings/issue-trackers/{id}"
                if matches!(method, "post" | "put") =>
            {
                operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                    "type":"object","required":["name","provider","urlTemplate"],
                    "properties":{
                        "name":{"type":"string","maxLength":100},
                        "provider":{"type":"string","enum":crate::issue_trackers::PROVIDERS},
                        "urlTemplate":{"type":"string","maxLength":1900,
                            "examples":["https://tracker.example.com/browse/{id}"]}
                    }
                }}}});
            }
            "/settings/report-branding" => {
                let content = json!({"application/json":{"schema":{"type":"object",
                    "required":["organization","footer","hasLogo","sampleScanId"], "properties":{
                        "organization":{"type":"string"},
                        "footer":{"type":"string"},
                        "hasLogo":{"type":"boolean"},
                        "sampleScanId":{"type":["string","null"], "format":"uuid"}
                    }
                }}});
                operation["responses"]["2XX"]["content"] = content;
                if method == "put" {
                    operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                        "type":"object","required":["organization"],"properties":{
                            "organization":{"type":"string","maxLength":100},
                            "footer":{"type":"string","maxLength":200}
                        }
                    }}}});
                }
            }
            "/settings/report-branding/logo" => {
                let content = json!({
                    "image/png":{"schema":{"type":"string","format":"binary"}},
                    "image/jpeg":{"schema":{"type":"string","format":"binary"}}
                });
                if method == "put" {
                    operation["requestBody"] =
                        json!({"required":true,"description":"Maximum 1 MB.", "content":content});
                } else if method == "get" {
                    operation["responses"]["2XX"]["content"] = content;
                }
            }
            "/settings/scanners" => {
                operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                    "type":"object", "required":["scanners"], "properties":{"scanners":{"type":"array",
                    "description":"An empty list restores deployment defaults.", "items":{"type":"string","enum":crate::artifacts::TOOLS}}}
                }}}});
            }
            "/registries/{id}/webhook" if method == "post" => {
                operation.as_object_mut().unwrap().remove("requestBody");
                operation["description"] = json!(
                    "Returns the token once. A new token replaces any existing token for this connection."
                );
            }
            "/webhooks/registries/{id}/ci" => {
                operation["security"] = json!([{"RegistryWebhookToken":[]}]);
                operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                    "type":"object", "required":["reference"], "properties":{
                        "reference":{"type":"string","examples":["registry.example.com/team/app:release"]},
                        "platform":{"type":"string","enum":crate::PLATFORMS,"default":crate::PLATFORMS[0]}
                    }
                }}}});
            }
            "/webhooks/registries/{id}/harbor" => {
                operation["security"] = json!([{"RegistryWebhookToken":[]}]);
                operation["description"] = json!(
                    "Use a Harbor HTTP webhook for Artifact pushed. Default and CloudEvents push payloads are accepted. Harbor's Auth Header can contain the raw token."
                );
            }
            "/webhooks/registries/{id}/ci/{scan_id}" => {
                operation["security"] = json!([{"RegistryWebhookToken":[]}]);
                operation["description"] = json!(
                    "Available for 24 hours after the latest CI submission. Counts require a complete vulnerability observation."
                );
                operation["responses"] = json!({
                    "200":{"description":"CI scan status and summary"},
                    "401":{"description":"Missing or invalid registry webhook token"},
                    "404":{"description":"Scan was not submitted to this CI endpoint or the result window expired"}
                });
            }
            _ => {}
        }
        if path.starts_with("/auth/") || path.starts_with("/users") || path == "/settings/sso" {
            describe_auth(path, method, &mut operation);
        }
        if method != "get" && matches!(access, Access::Session(_) | Access::PublicMutation) {
            operation["parameters"].as_array_mut().unwrap().push(json!({
                "name":"Origin", "in":"header", "required":true, "schema":{"type":"string"},
                "description":"Exact browser origin serving Certhia, including scheme and any non-default port."
            }));
        }
        if path.starts_with("/webhooks/") && method == "post" {
            operation["responses"] = json!({
                "200":{"description":"Non-push Harbor event ignored"},
                "202":{"description":"Request accepted, returning scanIds and the number of newly queued scans"},
                "400":{"description":"Invalid image, platform, or event"},
                "401":{"description":"Missing or invalid registry webhook token"},
                "429":{"description":"Scan queue has insufficient space"}
            });
        }
        endpoints.entry(path).or_insert_with(|| json!({}))[method] = operation;
    }
    json!({"openapi":"3.1.0","info":{"title":crate::PRODUCT_NAME,"version":env!("CARGO_PKG_VERSION")},
    "servers":[{"url":"/api"}],"paths":endpoints,
    "components":{"securitySchemes":{
        "RegistryWebhookToken":{"type":"http","scheme":"bearer"},
        "SessionCookie":{"type":"apiKey","in":"cookie","name":"__Host-certhia_session"},
        "LocalSessionCookie":{"type":"apiKey","in":"cookie","name":"certhia_session","description":"Plain HTTP on loopback only"}
    },"schemas":{"User":{"type":"object","required":["id","email","displayName","role","disabled","hasPassword"],
        "properties":{"id":{"type":"string","format":"uuid"},"email":{"type":"string","format":"email"},
            "displayName":{"type":"string"},"role":{"enum":[Role::Viewer,Role::Operator,Role::Admin]},
            "disabled":{"type":"boolean"},"hasPassword":{"type":"boolean"}}
    }}}})
}

fn describe_auth(path: &str, method: &str, operation: &mut Value) {
    let email = json!({"type":"string","format":"email","maxLength":254});
    let name = json!({"type":"string","maxLength":100});
    let password = json!({"type":"string","format":"password","minLength":12});
    let role = json!({"type":"string","enum":["viewer","operator","admin"]});
    let user = json!({"$ref":"#/components/schemas/User"});
    let sso_settings = json!({"type":"object","required":["name","issuer","clientId","allowedDomains","enabled","jit","trustEmail","secretPost"],
        "properties":{"name":name,"issuer":{"type":"string","format":"uri"},"clientId":{"type":"string"},
        "allowedDomains":{"type":"array","items":{"type":"string"}},"enabled":{"type":"boolean"},"jit":{"type":"boolean"},
        "trustEmail":{"type":"boolean"},"secretPost":{"type":"boolean"}}});
    let request = match (path, method) {
        ("/auth/setup", _) => {
            json!({"type":"object","required":["email","displayName","password","setupCode"],
            "properties":{"email":email,"displayName":name,"password":password,"setupCode":{"type":"string","format":"password"}}})
        }
        ("/auth/login", _) => json!({"type":"object","required":["email","password"],
            "properties":{"email":email,"password":{"type":"string","format":"password"}}}),
        ("/auth/password", _) => {
            json!({"type":"object","required":["currentPassword","newPassword"],
            "properties":{"currentPassword":{"type":"string","format":"password"},"newPassword":password}})
        }
        ("/settings/sso", "put") => json!({"type":"object","required":["settings"],
            "properties":{"settings":sso_settings,"clientSecret":{"type":"string","format":"password","writeOnly":true}}}),
        ("/users", "post") => json!({"type":"object","required":["email","displayName","role"],
            "properties":{"email":email,"displayName":name,"role":role,"password":password},
            "description":"Omit password for an account that signs in through a provider with email linking."}),
        ("/users/{id}", _) => json!({"type":"object","required":["role","disabled"],
            "properties":{"displayName":name,"role":role,"disabled":{"type":"boolean"},"newPassword":password},
                "description":"Set newPassword to reset another local user's password and revoke their sessions."}),
        _ => Value::Null,
    };
    if request.is_null() {
        operation.as_object_mut().unwrap().remove("requestBody");
    } else {
        operation["requestBody"] =
            json!({"required":true,"content":{"application/json":{"schema":request}}});
    }

    let response = match (path, method) {
        ("/auth/status", _) => json!({"type":"object","properties":{"local":{"type":"boolean"},
            "setupRequired":{"type":"boolean"},"providers":{"type":"array","items":{"type":"object",
                "properties":{"id":{"type":"string"},"name":{"type":"string"}}}}}}),
        ("/auth/me", _) => {
            json!({"type":"object","properties":{"user":user,"local":{"type":"boolean"},
            "oidcEmailLinking":{"type":"boolean"}}})
        }
        ("/settings/sso", _) => json!({"type":"object","properties":{"settings":{"anyOf":[sso_settings,{"type":"null"}]},
            "callbackUrl":{"type":["string","null"],"format":"uri"},"deploymentConflict":{"type":"boolean"},
            "deploymentProviders":{"type":"array","items":{"type":"string"}}}}),
        ("/users", "get") => json!({"type":"array","items":user}),
        ("/auth/setup" | "/auth/login" | "/users" | "/users/{id}", _) => user,
        _ => Value::Null,
    };
    if !response.is_null() {
        operation["responses"]["2XX"]["content"] = json!({"application/json":{"schema":response}});
    }
    match path {
        "/auth/login" | "/auth/setup" | "/auth/oidc/{provider}/start" => {
            operation["responses"]["403"] =
                json!({"description":"Sign-in method unavailable or request origin rejected"});
            operation["responses"]["429"] = json!({"description":"Attempt limit reached"});
            if path == "/auth/login" {
                operation["responses"]["401"] = json!({"description":"Invalid credentials"});
            }
        }
        "/auth/password" => {
            operation["responses"]["429"] = json!({"description":"Attempt limit reached"})
        }
        _ => {}
    }
    match path {
        "/auth/oidc/{provider}/start" | "/auth/oidc/{provider}/callback" => {
            operation["responses"]
                .as_object_mut()
                .unwrap()
                .remove("2XX");
            operation["responses"]["303"] =
                json!({"description":"Continue the OIDC flow or return to Certhia"});
        }
        "/auth/logout" | "/auth/password" | "/users/{id}/sessions/revoke" => {
            operation["responses"]
                .as_object_mut()
                .unwrap()
                .remove("2XX");
            operation["responses"]["204"] = json!({"description":"Sessions revoked"});
        }
        _ => {}
    }
}

pub async fn schema() -> Json<Value> {
    Json(document())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_describes_dashboard_and_machine_authentication() {
        let doc = document();
        let paths = &doc["paths"];
        assert_eq!(paths["/health"]["get"]["security"], Value::Null);
        assert_eq!(paths["/users"]["post"]["x-required-role"], "admin");
        assert_eq!(paths["/scans"]["get"]["x-required-role"], "viewer");
        assert_eq!(paths["/scans"]["post"]["x-required-role"], "operator");
        assert_eq!(
            paths["/webhooks/registries/{id}/ci"]["post"]["security"],
            json!([{"RegistryWebhookToken":[]}])
        );
    }
}
