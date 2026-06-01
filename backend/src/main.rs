use axum::{
    extract::Json,
    http::{HeaderValue, Method},
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use tracing::info;

#[derive(Deserialize)]
struct ScanRequest {
    domain: String,
}

#[derive(Serialize, Clone)]
struct CheckResult {
    name: String,
    status: String,
    value: String,
    message: String,
    fix: String,
}

#[derive(Serialize, Clone)]
struct EmailProvider {
    name: String,
    icon: String,
    color: String,
    mx_hint: String,
}

#[derive(Serialize)]
struct ScanResponse {
    domain: String,
    grade: String,
    score: u32,
    checks: Vec<CheckResult>,
    summary: String,
    email_provider: EmailProvider,
}

async fn build_resolver() -> TokioAsyncResolver {
    TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default())
}

async fn check_spf(resolver: &TokioAsyncResolver, domain: &str) -> CheckResult {
    match resolver.txt_lookup(domain).await {
        Ok(records) => {
            let spf_record = records
                .iter()
                .flat_map(|r| r.iter())
                .map(|r| String::from_utf8_lossy(r).to_string())
                .find(|s| s.starts_with("v=spf1"));

            match spf_record {
                Some(record) => {
                    let has_all = record.contains("-all") || record.contains("~all");
                    if record.contains("-all") {
                        CheckResult {
                            name: "SPF Record".to_string(),
                            status: "pass".to_string(),
                            value: record,
                            message: "SPF record found with strict policy (-all)".to_string(),
                            fix: String::new(),
                        }
                    } else if has_all {
                        CheckResult {
                            name: "SPF Record".to_string(),
                            status: "warning".to_string(),
                            value: record,
                            message: "SPF found but uses soft fail (~all). Consider -all for stricter policy.".to_string(),
                            fix: "Change ~all to -all at the end of your SPF record for stronger protection.".to_string(),
                        }
                    } else {
                        CheckResult {
                            name: "SPF Record".to_string(),
                            status: "warning".to_string(),
                            value: record,
                            message: "SPF record found but missing an 'all' mechanism.".to_string(),
                            fix: "Add -all to the end of your SPF TXT record to block all unauthorized senders.".to_string(),
                        }
                    }
                }
                None => CheckResult {
                    name: "SPF Record".to_string(),
                    status: "fail".to_string(),
                    value: "Not found".to_string(),
                    message: "No SPF record found for this domain.".to_string(),
                    fix: "Add a TXT record: v=spf1 include:_spf.yourmailprovider.com -all".to_string(),
                },
            }
        }
        Err(_) => CheckResult {
            name: "SPF Record".to_string(),
            status: "fail".to_string(),
            value: "DNS lookup failed".to_string(),
            message: "Could not resolve DNS for this domain.".to_string(),
            fix: "Ensure your domain has valid DNS and add a TXT record for SPF.".to_string(),
        },
    }
}

async fn check_dmarc(resolver: &TokioAsyncResolver, domain: &str) -> CheckResult {
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(&dmarc_domain).await {
        Ok(records) => {
            let dmarc_record = records
                .iter()
                .flat_map(|r| r.iter())
                .map(|r| String::from_utf8_lossy(r).to_string())
                .find(|s| s.starts_with("v=DMARC1"));

            match dmarc_record {
                Some(record) => {
                    if record.contains("p=reject") {
                        CheckResult {
                            name: "DMARC Policy".to_string(),
                            status: "pass".to_string(),
                            value: record,
                            message: "DMARC found with reject policy — strongest protection.".to_string(),
                            fix: String::new(),
                        }
                    } else if record.contains("p=quarantine") {
                        CheckResult {
                            name: "DMARC Policy".to_string(),
                            status: "warning".to_string(),
                            value: record,
                            message: "DMARC found with quarantine policy. Consider upgrading to reject.".to_string(),
                            fix: "Update your DMARC policy from p=quarantine to p=reject for maximum protection.".to_string(),
                        }
                    } else {
                        CheckResult {
                            name: "DMARC Policy".to_string(),
                            status: "warning".to_string(),
                            value: record,
                            message: "DMARC found with p=none — monitoring mode only, not enforcing.".to_string(),
                            fix: "Move from p=none to p=quarantine then p=reject once you've verified legitimate senders.".to_string(),
                        }
                    }
                }
                None => CheckResult {
                    name: "DMARC Policy".to_string(),
                    status: "fail".to_string(),
                    value: "Not found".to_string(),
                    message: "No DMARC record found.".to_string(),
                    fix: "Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com".to_string(),
                },
            }
        }
        Err(_) => CheckResult {
            name: "DMARC Policy".to_string(),
            status: "fail".to_string(),
            value: "Not found".to_string(),
            message: "DMARC record not found or DNS error.".to_string(),
            fix: "Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com".to_string(),
        },
    }
}

async fn check_dkim(resolver: &TokioAsyncResolver, domain: &str) -> CheckResult {
    let selectors = vec!["default", "google", "mail", "dkim", "k1", "selector1", "selector2"];
    for selector in selectors {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        if let Ok(records) = resolver.txt_lookup(&dkim_domain).await {
            let found = records
                .iter()
                .flat_map(|r| r.iter())
                .map(|r| String::from_utf8_lossy(r).to_string())
                .any(|s| s.contains("p=") && !s.contains("p=\"\""));
            if found {
                return CheckResult {
                    name: "DKIM Signing".to_string(),
                    status: "pass".to_string(),
                    value: format!("Found at selector: {}", selector),
                    message: format!("DKIM record found using selector '{}'.", selector),
                    fix: String::new(),
                };
            }
        }
    }
    CheckResult {
        name: "DKIM Signing".to_string(),
        status: "warning".to_string(),
        value: "Not detected".to_string(),
        message: "No DKIM record found for common selectors. DKIM may be set up with a custom selector.".to_string(),
        fix: "Contact your email provider for your DKIM selector and add the TXT record they provide to your DNS.".to_string(),
    }
}

async fn check_mx(resolver: &TokioAsyncResolver, domain: &str) -> CheckResult {
    match resolver.mx_lookup(domain).await {
        Ok(records) => {
            let count = records.iter().count();
            let mx_list: Vec<String> = records
                .iter()
                .map(|r| format!("{} (priority {})", r.exchange(), r.preference()))
                .collect();
            if count >= 2 {
                CheckResult {
                    name: "MX Records".to_string(),
                    status: "pass".to_string(),
                    value: mx_list.join(", "),
                    message: format!("{} MX records found — good redundancy.", count),
                    fix: String::new(),
                }
            } else if count == 1 {
                CheckResult {
                    name: "MX Records".to_string(),
                    status: "warning".to_string(),
                    value: mx_list.join(", "),
                    message: "Only 1 MX record found. Consider adding a backup for redundancy.".to_string(),
                    fix: "Add a secondary MX record with a higher priority number for redundancy.".to_string(),
                }
            } else {
                CheckResult {
                    name: "MX Records".to_string(),
                    status: "fail".to_string(),
                    value: "None found".to_string(),
                    message: "No MX records found — this domain cannot receive email.".to_string(),
                    fix: "Add MX records pointing to your mail server. Example: 10 mail.yourdomain.com".to_string(),
                }
            }
        }
        Err(_) => CheckResult {
            name: "MX Records".to_string(),
            status: "fail".to_string(),
            value: "DNS error".to_string(),
            message: "Could not look up MX records.".to_string(),
            fix: "Add valid MX records for your domain.".to_string(),
        },
    }
}

async fn check_blacklist(resolver: &TokioAsyncResolver, domain: &str) -> CheckResult {
    let rbls = vec![
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    ];

    let mx_ip = match resolver.mx_lookup(domain).await {
        Ok(records) => {
            let first_mx = records.iter().next().map(|r| r.exchange().to_string());
            match first_mx {
                Some(host) => match resolver.ipv4_lookup(&host).await {
                    Ok(ips) => ips.iter().next().map(|ip| ip.to_string()),
                    Err(_) => None,
                },
                None => None,
            }
        }
        Err(_) => None,
    };

    match mx_ip {
        Some(ip) => {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() != 4 {
                return CheckResult {
                    name: "Blacklist Status".to_string(),
                    status: "warning".to_string(),
                    value: "Could not resolve MX IP".to_string(),
                    message: "Unable to resolve mail server IP for blacklist check.".to_string(),
                    fix: String::new(),
                };
            }
            let reversed_ip = format!("{}.{}.{}.{}", parts[3], parts[2], parts[1], parts[0]);
            let mut listed_on: Vec<String> = Vec::new();

            for rbl in &rbls {
                let query = format!("{}.{}", reversed_ip, rbl);
                if resolver.ipv4_lookup(&query).await.is_ok() {
                    listed_on.push(rbl.to_string());
                }
            }

            if listed_on.is_empty() {
                CheckResult {
                    name: "Blacklist Status".to_string(),
                    status: "pass".to_string(),
                    value: format!("IP {} — clean", ip),
                    message: "Mail server IP is not listed on any major blacklists.".to_string(),
                    fix: String::new(),
                }
            } else {
                CheckResult {
                    name: "Blacklist Status".to_string(),
                    status: "fail".to_string(),
                    value: format!("Listed on: {}", listed_on.join(", ")),
                    message: format!("Your mail server IP ({}) is blacklisted!", ip),
                    fix: format!(
                        "Request delisting from: {}. Check MXToolbox for delisting links.",
                        listed_on.join(", ")
                    ),
                }
            }
        }
        None => CheckResult {
            name: "Blacklist Status".to_string(),
            status: "warning".to_string(),
            value: "No MX IP found".to_string(),
            message: "Could not resolve mail server IP to check blacklists.".to_string(),
            fix: "Ensure your MX records point to a valid mail server.".to_string(),
        },
    }
}

fn calculate_grade(checks: &[CheckResult]) -> (String, u32) {
    let mut score: u32 = 0;
    let weights = [30u32, 25, 20, 15, 10];

    for (i, check) in checks.iter().enumerate() {
        let weight = weights.get(i).copied().unwrap_or(10);
        match check.status.as_str() {
            "pass" => score += weight,
            "warning" => score += weight / 2,
            _ => {}
        }
    }

    let grade = match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        45..=59 => "D",
        _ => "F",
    };

    (grade.to_string(), score)
}

fn build_summary(grade: &str, score: u32, checks: &[CheckResult]) -> String {
    let fails = checks.iter().filter(|c| c.status == "fail").count();
    let warnings = checks.iter().filter(|c| c.status == "warning").count();
    match grade {
        "A" => format!("Excellent! Score: {}/100. Your domain is well-configured for email deliverability.", score),
        "B" => format!("Good. Score: {}/100. {} warning(s) to address for better deliverability.", score, warnings),
        "C" => format!("Fair. Score: {}/100. {} issue(s) found — fix these to avoid the spam folder.", score, fails + warnings),
        "D" => format!("Poor. Score: {}/100. {} critical issue(s) affecting deliverability.", score, fails),
        _ => format!("Critical. Score: {}/100. {} major issue(s) — emails likely going to spam.", score, fails),
    }
}


fn detect_email_provider(mx_records: &str) -> EmailProvider {
    let mx = mx_records.to_lowercase();
    if mx.contains("google") || mx.contains("googlemail") || mx.contains("aspmx") {
        EmailProvider { name: "Google Workspace".to_string(), icon: "G".to_string(), color: "#4285F4".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("outlook") || mx.contains("microsoft") || mx.contains("hotmail") || mx.contains("office365") {
        EmailProvider { name: "Microsoft 365".to_string(), icon: "M".to_string(), color: "#0078D4".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("zoho") {
        EmailProvider { name: "Zoho Mail".to_string(), icon: "Z".to_string(), color: "#E50000".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("mimecast") {
        EmailProvider { name: "Mimecast".to_string(), icon: "MC".to_string(), color: "#FF6600".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("proofpoint") || mx.contains("pphosted") {
        EmailProvider { name: "Proofpoint".to_string(), icon: "PP".to_string(), color: "#0046AD".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("amazonses") || mx.contains("amazonaws") {
        EmailProvider { name: "Amazon SES".to_string(), icon: "AWS".to_string(), color: "#FF9900".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("sendgrid") {
        EmailProvider { name: "SendGrid".to_string(), icon: "SG".to_string(), color: "#1A82E2".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("mailgun") {
        EmailProvider { name: "Mailgun".to_string(), icon: "MG".to_string(), color: "#F06B66".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("fastmail") {
        EmailProvider { name: "Fastmail".to_string(), icon: "FM".to_string(), color: "#1A4A8A".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("yahoo") || mx.contains("yahoodns") {
        EmailProvider { name: "Yahoo Mail".to_string(), icon: "Y".to_string(), color: "#6001D2".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("icloud") || mx.contains("apple") {
        EmailProvider { name: "Apple iCloud".to_string(), icon: "A".to_string(), color: "#555555".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.contains("mailchimp") || mx.contains("mandrill") {
        EmailProvider { name: "Mailchimp".to_string(), icon: "MC".to_string(), color: "#FFE01B".to_string(), mx_hint: mx_records.to_string() }
    } else if mx.is_empty() || mx == "no mx ip found" || mx == "dns error" {
        EmailProvider { name: "Unknown".to_string(), icon: "?".to_string(), color: "#999999".to_string(), mx_hint: "No MX records found".to_string() }
    } else {
        EmailProvider { name: "Custom / Self-hosted".to_string(), icon: "✉".to_string(), color: "#555555".to_string(), mx_hint: mx_records.to_string() }
    }
}

async fn scan_domain(Json(payload): Json<ScanRequest>) -> ResponseJson<ScanResponse> {
    let domain = payload.domain.trim().to_lowercase();
    let domain = domain.trim_start_matches("http://").trim_start_matches("https://").trim_start_matches("www.");
    let domain = domain.split('/').next().unwrap_or(&domain).to_string();

    info!("Scanning domain: {}", domain);

    let resolver = build_resolver().await;

    let (spf, dmarc, dkim, mx, blacklist) = tokio::join!(
        check_spf(&resolver, &domain),
        check_dmarc(&resolver, &domain),
        check_dkim(&resolver, &domain),
        check_mx(&resolver, &domain),
        check_blacklist(&resolver, &domain),
    );

    let mx_value = mx.value.clone();
    let checks = vec![spf, dmarc, dkim, mx, blacklist];
    let (grade, score) = calculate_grade(&checks);
    let summary = build_summary(&grade, score, &checks);
    let email_provider = detect_email_provider(&mx_value);

    ResponseJson(ScanResponse {
        domain,
        grade,
        score,
        checks,
        summary,
        email_provider,
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/scan", post(scan_domain))
        .layer(cors);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();

    info!("Email Health Scanner API running on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}