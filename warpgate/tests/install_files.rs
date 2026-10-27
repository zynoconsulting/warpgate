use std::process::Command;

fn install_config(config: &str, variables: &str, environment: &[(&str, &str)]) -> String {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("warpgate.yaml"), config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_warpgate"))
        .args([
            "--skip-securing-files",
            "internal-install-files",
            "--substitute-env",
            variables,
        ])
        .arg(source.path())
        .arg(destination.path())
        .env_remove("WARPGATE_CONFIG")
        .envs(environment.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "installer failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read_to_string(destination.path().join("warpgate.yaml")).unwrap()
}

#[test]
fn expands_nested_values_in_the_requested_order() {
    let installed = install_config(
        "database_url: $DATABASE_URL\n",
        "DATABASE_URL DATABASE_PASSWORD",
        &[
            (
                "DATABASE_URL",
                "postgres://warpgate:$DATABASE_PASSWORD@database/warpgate",
            ),
            ("DATABASE_PASSWORD", "s&/cret$UNLISTED\\suffix"),
        ],
    );

    assert_eq!(
        installed,
        "database_url: postgres://warpgate:s&/cret$UNLISTED\\suffix@database/warpgate\n"
    );
}

#[test]
fn matches_complete_variable_names_in_any_order() {
    let installed = install_config(
        "pass=$PASS\nhost=$PASSWORD_HOST\nunselected=$PASS_SUFFIX\n",
        "PASS PASSWORD_HOST",
        &[("PASS", "secret"), ("PASSWORD_HOST", "database")],
    );

    assert_eq!(
        installed,
        "pass=secret\nhost=database\nunselected=$PASS_SUFFIX\n"
    );
}
