use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TF_ARC_SOURCE_REVISION");
    let revision = std::env::var("TF_ARC_SOURCE_REVISION").unwrap_or_else(|_| {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("source revision required");
        assert!(output.status.success(), "source revision required");
        String::from_utf8(output.stdout)
            .expect("revision encoding")
            .trim()
            .to_owned()
    });
    assert!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid source revision"
    );
    println!("cargo:rustc-env=TF_ARC_SOURCE_REVISION={revision}");
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        && output.status.success()
    {
        let git_dir = String::from_utf8(output.stdout).expect("git path encoding");
        let git_dir = git_dir.trim();
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/refs/heads");
        println!("cargo:rerun-if-changed={git_dir}/packed-refs");
    }
}
