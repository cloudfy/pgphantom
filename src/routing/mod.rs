use crate::config::{BackendConfig, RegexRule, RoutingConfig, TlsConfig};
use crate::errors::RoutingError;
use regex::Regex;

// ---------------------------------------------------------------------------
// Resolved route
// ---------------------------------------------------------------------------

/// A fully resolved backend endpoint, produced by the `RouteResolver`.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub host: String,
    pub port: u16,
    /// The database name to send to the backend (possibly rewritten).
    pub database: String,
    /// The username to send to the backend (possibly rewritten).
    pub user: String,
    pub tls: TlsConfig,
    /// In JWT mode: static service username for the backend connection.
    pub service_user: Option<String>,
    /// In JWT mode: env var for the backend password.
    pub service_password_env: Option<String>,
}

// ---------------------------------------------------------------------------
// Route resolver
// ---------------------------------------------------------------------------

pub struct RouteResolver {
    config: RoutingConfig,
    /// Pre-compiled regexes for `regex_rules`, matched by rule index.
    compiled: Vec<CompiledRegexRule>,
}

struct CompiledRegexRule {
    db_regex: Option<Regex>,
    user_regex: Option<Regex>,
    rule: RegexRule,
}

impl RouteResolver {
    pub fn new(config: RoutingConfig) -> Result<Self, RoutingError> {
        let mut compiled = Vec::new();
        for rule in &config.regex_rules {
            compiled.push(CompiledRegexRule {
                db_regex: rule
                    .match_database
                    .as_deref()
                    .map(Regex::new)
                    .transpose()?,
                user_regex: rule
                    .match_user
                    .as_deref()
                    .map(Regex::new)
                    .transpose()?,
                rule: rule.clone(),
            });
        }
        Ok(Self { config, compiled })
    }

    /// Resolve a backend for the given `database` and `user`.
    ///
    /// Evaluation order:
    ///  1. Exact `mappings` (first match wins)
    ///  2. Regex `regex_rules` (first match wins, with capture-group substitution)
    ///  3. `default_backend` if configured
    ///  4. `RoutingError::NoRoute`
    pub fn resolve(&self, database: &str, user: &str) -> Result<ResolvedRoute, RoutingError> {
        // 1. Exact mappings
        for mapping in &self.config.mappings {
            let db_match = mapping.database.as_deref().map_or(true, |d| d == database);
            let user_match = mapping.user.as_deref().map_or(true, |u| u == user);
            if db_match && user_match {
                let backend = self.config.backends.get(&mapping.backend).expect(
                    "config validation should have caught missing backend reference",
                );
                let resolved_db = mapping
                    .rewrite_database
                    .as_deref()
                    .unwrap_or(database)
                    .to_string();
                return Ok(route_from_backend(backend, resolved_db, user.to_string()));
            }
        }

        // 2. Regex rules
        for compiled in &self.compiled {
            let db_caps = match &compiled.db_regex {
                Some(re) => re.captures(database),
                None => None,
            };
            let user_caps = match &compiled.user_regex {
                Some(re) => re.captures(user),
                None => None,
            };

            let db_matched = compiled.db_regex.as_ref().map_or(true, |_| db_caps.is_some());
            let user_matched = compiled
                .user_regex
                .as_ref()
                .map_or(true, |_| user_caps.is_some());

            if !db_matched || !user_matched {
                continue;
            }

            let rule = &compiled.rule;

            // Determine the backend.
            if let Some(name) = &rule.backend {
                let backend = self.config.backends.get(name).expect(
                    "config validation should have caught missing backend reference",
                );
                let resolved_db = rule
                    .rewrite_database
                    .as_deref()
                    .map(|t| apply_captures(t, database, db_caps.as_ref()))
                    .unwrap_or_else(|| database.to_string());
                return Ok(route_from_backend(backend, resolved_db, user.to_string()));
            }

            if let Some(host_template) = &rule.backend_host {
                let host = apply_captures(host_template, database, db_caps.as_ref());
                let resolved_db = rule
                    .rewrite_database
                    .as_deref()
                    .map(|t| apply_captures(t, database, db_caps.as_ref()))
                    .unwrap_or_else(|| database.to_string());
                let tls = rule
                    .backend_tls
                    .clone()
                    .unwrap_or_default();
                return Ok(ResolvedRoute {
                    host,
                    port: rule.backend_port,
                    database: resolved_db,
                    user: user.to_string(),
                    tls,
                    service_user: None,
                    service_password_env: None,
                });
            }
        }

        // 3. Default backend
        if let Some(name) = &self.config.default_backend {
            let backend = self.config.backends.get(name).expect(
                "config validation should have caught missing backend reference",
            );
            return Ok(route_from_backend(
                backend,
                database.to_string(),
                user.to_string(),
            ));
        }

        Err(RoutingError::NoRoute {
            database: database.to_string(),
            user: user.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn route_from_backend(
    backend: &BackendConfig,
    database: String,
    user: String,
) -> ResolvedRoute {
    ResolvedRoute {
        host: backend.host.clone(),
        port: backend.port,
        database,
        user,
        tls: backend.tls.clone(),
        service_user: backend.service_user.clone(),
        service_password_env: backend.service_password_env.clone(),
    }
}

/// Substitute `$1`, `$2`, … in a template string with regex capture groups.
fn apply_captures(template: &str, input: &str, caps: Option<&regex::Captures<'_>>) -> String {
    let Some(caps) = caps else {
        return template.to_string();
    };
    let mut result = template.to_string();
    for i in 1..caps.len() {
        if let Some(m) = caps.get(i) {
            result = result.replace(&format!("${i}"), m.as_str());
        }
    }
    // $0 = whole match
    if let Some(m) = caps.get(0) {
        result = result.replace("$0", m.as_str());
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendConfig, RoutingConfig, MappingRule, TlsConfig};
    use std::collections::HashMap;

    fn make_backend() -> BackendConfig {
        BackendConfig {
            host: "pg-primary".into(),
            port: 5432,
            tls: TlsConfig::default(),
            service_user: None,
            service_password_env: None,
        }
    }

    #[test]
    fn test_exact_mapping() {
        let mut backends = HashMap::new();
        backends.insert("primary".to_string(), make_backend());
        let config = RoutingConfig {
            mappings: vec![MappingRule {
                database: Some("myapp".into()),
                user: None,
                backend: "primary".into(),
                rewrite_database: None,
            }],
            regex_rules: vec![],
            backends,
            default_backend: None,
        };
        let resolver = RouteResolver::new(config).unwrap();
        let route = resolver.resolve("myapp", "alice").unwrap();
        assert_eq!(route.host, "pg-primary");
    }

    #[test]
    fn test_no_route() {
        let config = RoutingConfig {
            mappings: vec![],
            regex_rules: vec![],
            backends: HashMap::new(),
            default_backend: None,
        };
        let resolver = RouteResolver::new(config).unwrap();
        assert!(resolver.resolve("unknown", "alice").is_err());
    }

    #[test]
    fn test_regex_rule() {
        let mut backends = HashMap::new();
        backends.insert("primary".to_string(), make_backend());
        let config = RoutingConfig {
            mappings: vec![],
            regex_rules: vec![crate::config::RegexRule {
                match_database: Some("^prod_(.+)$".into()),
                match_user: None,
                backend: Some("primary".into()),
                backend_host: None,
                backend_port: 5432,
                rewrite_database: Some("$1".into()),
                backend_tls: None,
            }],
            backends,
            default_backend: None,
        };
        let resolver = RouteResolver::new(config).unwrap();
        let route = resolver.resolve("prod_appdb", "alice").unwrap();
        assert_eq!(route.database, "appdb");
    }
}
