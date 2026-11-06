//! `aevan auth-probe` — stage 1, credential-free.
//!
//! Reports the TLS chain, every redirect hop, the final status and the detected
//! form shape. It is safe to run repeatedly: no credential is read or sent and
//! a pre-auth failure costs no login attempt.

use serde::Serialize;

use aevan_core::{AevanError, AevanResult};
use aevan_nc::{AuthObservation, AuthProbe, FormShape};

use crate::common;

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    #[serde(flatten)]
    observation: AuthObservation,
}

/// Run the probe.
pub fn run(url_arg: Option<&str>, profile: Option<&str>, json: bool) -> AevanResult<()> {
    let url = common::resolve_url(url_arg, profile)?;
    let observation = AuthProbe::new()
        .probe(&url)
        .map_err(common::network_error)?;

    let report = Report {
        schema_version: common::SCHEMA_VERSION,
        observation,
    };

    if json {
        let text = serde_json::to_string_pretty(&report).map_err(|error| {
            AevanError::Config(format!("cannot serialise probe output: {error}"))
        })?;
        println!("{text}");
    } else {
        print_human(&report.observation);
    }

    Ok(())
}

fn print_human(observation: &AuthObservation) {
    println!("aevan auth-probe (schema {})", common::SCHEMA_VERSION);
    println!("  url: {}", observation.url);
    println!(
        "  tls: {} ({} certificate(s))",
        observation.tls.protocol,
        observation.tls.chain.len()
    );
    for (index, certificate) in observation.tls.chain.iter().enumerate() {
        println!("    [{index}] subject: {}", certificate.subject);
        println!("        issuer:  {}", certificate.issuer);
    }

    println!("  redirects:");
    for hop in &observation.redirects {
        let location = hop.location.as_deref().unwrap_or("-");
        println!(
            "    {} -> {} {} (location: {})",
            hop.url, hop.status_code, hop.reason, location
        );
    }
    println!(
        "  final: {} {} {}",
        observation.final_status, observation.final_reason, observation.final_url
    );

    let shape = match observation.form_shape {
        FormShape::None => "none",
        FormShape::Login => "login",
        FormShape::Token => "token",
    };
    println!("  form shape: {shape}");
    println!(
        "  fields: login-form={} realm={} token={}",
        observation.login_form_present,
        observation.realm_field_present,
        observation.token_field_present
    );
    if let Some(action) = &observation.login_action {
        println!("  login action: {action}");
    }
    if observation.redirect_limit_reached {
        println!("  note: the redirect hop limit was reached");
    }
}
