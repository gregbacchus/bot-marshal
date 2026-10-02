use marshal_config::model::Config;

#[test]
fn native_decision_judge_config_loads_for_both_services() {
    for provider in ["system_one", "decisions_api"] {
        let yaml = format!(
            "profile:\n  default_action: deny\n  policy:\n    - layer: judge\n      provider:\n        type: {provider}\n        model: jev-latest\n        api_key_env: DECISION_KEY\n        min_confidence: 0.9\n      prompt: Permit only repository reads.\n"
        );
        let parsed = serde_yaml_ng::from_str::<Config>(&yaml);
        assert!(parsed.is_ok(), "{provider}: {parsed:?}");
    }
}

#[test]
fn invalid_confidence_has_an_exact_config_diagnostic() {
    for threshold in ["-0.1", "1.1", ".nan"] {
        let yaml = format!(
            "profile:\n  default_action: deny\n  policy:\n    - layer: judge\n      provider: {{type: decisions_api, model: m, api_key_env: K, min_confidence: {threshold}}}\n      prompt: Test\n"
        );
        let cfg: Config = serde_yaml_ng::from_str(&yaml).unwrap();
        assert!(
            marshal_config::validate(&cfg)
                .iter()
                .any(|d| d.location == "profile.policy[0].provider.min_confidence"
                    && d.severity == marshal_config::Severity::Error)
        );
    }
}
