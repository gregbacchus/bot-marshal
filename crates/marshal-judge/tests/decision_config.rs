use marshal_config::model::Config;

fn config(provider: &str) -> Config {
    serde_yaml_ng::from_str(&format!(
        "profile:\n  default_action: deny\n  policy:\n    - layer: judge\n      provider: {provider}\n      prompt: Permit only repository reads.\n"
    )).unwrap()
}

#[test]
fn dialect_selects_judge_and_options() {
    for provider in [
        "{dialect: openai, model: m, api_key_env: K}",
        "{dialect: anthropic, model: m, api_key_env: K}",
        "{dialect: system_one, model: nimble, base_url: 'http://localhost:11434'}",
        "{dialect: system_one, model: jev-latest, base_url: 'https://api.typesafe.ai', api_key_env: K}",
    ] {
        assert!(
            !marshal_config::validate(&config(provider))
                .iter()
                .any(|d| d.severity == marshal_config::Severity::Error)
        );
    }
}

#[test]
fn invalid_confidence_has_an_exact_config_diagnostic() {
    for threshold in ["-0.1", "1.1", ".nan"] {
        let cfg = config(&format!(
            "{{dialect: system_one, base_url: 'http://localhost:11434', model: m, min_confidence: {threshold}}}"
        ));
        assert!(
            marshal_config::validate(&cfg)
                .iter()
                .any(|d| d.location == "profile.policy[0].provider.min_confidence"
                    && d.severity == marshal_config::Severity::Error)
        );
    }
}

#[test]
fn removed_provider_names_and_missing_required_fields_are_rejected() {
    for provider in [
        "{type: openai, model: m, api_key_env: K}",
        "{type: anthropic, model: m, api_key_env: K}",
        "{type: system_one, model: m, api_key_env: K}",
        "{type: decisions_api, model: m, api_key_env: K}",
        "{dialect: system_one, model: m}",
        "{model: m, api_key_env: K}",
        "{dialect: openai, type: llm, model: m, api_key_env: K}",
        "{dialect: system_one, base_url: 'http://localhost:11434', model: m, max_tokens: 10}",
        "{dialect: openai, model: m, api_key_env: K, min_confidence: 0.9}",
    ] {
        assert!(serde_yaml_ng::from_str::<Config>(&format!("profile:\n  default_action: deny\n  policy:\n    - layer: judge\n      provider: {provider}\n      prompt: Test\n")).is_err());
    }
}
