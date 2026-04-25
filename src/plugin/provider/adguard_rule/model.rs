// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use regex::Regex;
use serde::Deserialize;

use crate::core::rule_matcher::DomainRuleMatcher;
use crate::proto::{Name, RecordType};

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct AdGuardRuleConfig {
    #[serde(default)]
    pub(super) rules: Vec<String>,
    #[serde(default)]
    pub(super) files: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct BuildStats {
    pub(super) total_rules: usize,
    pub(super) supported_rules: usize,
    pub(super) skipped_rules: usize,
    pub(super) exception_rules: usize,
    pub(super) important_rules: usize,
}

#[derive(Debug, Clone)]
pub(super) struct RuleInput {
    pub(super) raw: String,
    pub(super) source: String,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedRule {
    pub(super) source: String,
    pub(super) expression: String,
    pub(super) matcher: PatternMatcher,
    pub(super) matcher_key: String,
    pub(super) is_exception: bool,
    pub(super) important: bool,
    pub(super) badfilter: bool,
    pub(super) dnstype: Option<DnsTypeConstraint>,
    pub(super) denyallow: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledRule {
    pub(super) matcher: PatternMatcher,
    pub(super) dnstype: Option<DnsTypeConstraint>,
    pub(super) denyallow: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct CompiledRuleSet {
    pub(super) fast_matcher: DomainRuleMatcher,
    pub(super) conditional_rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
pub(super) enum PatternMatcher {
    Exact(Box<str>),
    Domain(Box<str>),
    Prefix(Box<str>),
    Suffix(Box<str>),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub(super) enum DnsTypeConstraint {
    Allow(Vec<RecordType>),
    Deny(Vec<RecordType>),
}

impl CompiledRule {
    pub(super) fn is_match(&self, qname: &str, qtype: RecordType) -> bool {
        if let Some(dnstype) = &self.dnstype
            && !dnstype.matches(qtype)
        {
            return false;
        }

        if !self.matcher.is_match(qname) {
            return false;
        }

        if self
            .denyallow
            .iter()
            .any(|domain| matches_domain_or_subdomain(qname, domain))
        {
            return false;
        }

        true
    }

    pub(super) fn is_match_name_only(&self, qname: &str) -> bool {
        if self.dnstype.is_some() {
            return false;
        }

        if !self.matcher.is_match(qname) {
            return false;
        }

        if self
            .denyallow
            .iter()
            .any(|domain| matches_domain_or_subdomain(qname, domain))
        {
            return false;
        }

        true
    }
}

impl CompiledRuleSet {
    pub(super) fn finalize(&mut self) -> Result<(), String> {
        self.fast_matcher.finalize()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        !self.fast_matcher.has_rules() && self.conditional_rules.is_empty()
    }

    pub(super) fn is_match(&self, qname: &Name, qtype: RecordType) -> bool {
        self.fast_matcher.is_match_name(qname)
            || self
                .conditional_rules
                .iter()
                .any(|rule| rule.is_match(qname.normalized(), qtype))
    }

    pub(super) fn is_match_name_only(&self, qname: &Name) -> bool {
        self.fast_matcher.is_match_name(qname)
            || self
                .conditional_rules
                .iter()
                .any(|rule| rule.is_match_name_only(qname.normalized()))
    }
}

impl PatternMatcher {
    pub(super) fn is_match(&self, qname: &str) -> bool {
        match self {
            Self::Exact(domain) => qname == domain.as_ref(),
            Self::Domain(domain) => matches_domain_or_subdomain(qname, domain),
            Self::Prefix(prefix) => qname.starts_with(prefix.as_ref()),
            Self::Suffix(suffix) => qname.ends_with(suffix.as_ref()),
            Self::Regex(regex) => regex.is_match(qname),
        }
    }
}

impl DnsTypeConstraint {
    pub(super) fn matches(&self, qtype: RecordType) -> bool {
        match self {
            Self::Allow(allowed) => allowed.contains(&qtype),
            Self::Deny(denied) => !denied.contains(&qtype),
        }
    }
}

pub(super) fn matches_domain_or_subdomain(qname: &str, domain: &str) -> bool {
    qname == domain
        || qname.len() > domain.len()
            && qname.ends_with(domain)
            && qname.as_bytes()[qname.len() - domain.len() - 1] == b'.'
}
