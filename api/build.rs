use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let workspace_dir = PathBuf::from("../lite-web-client");
    let dist_dir = workspace_dir.join("dist");
    let src_dir = workspace_dir.join("src");
    let package_json = workspace_dir.join("package.json");
    let vite_config = workspace_dir.join("vite.config.js");
    let entry_html = workspace_dir.join("index.html");
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let staged_dist_dir = out_dir.join("lite-web-dist");

    println!("cargo:rerun-if-env-changed=AUTHOS_BUILD_VERSION");
    emit_rerun_if_changed(&package_json);
    emit_rerun_if_changed(&vite_config);
    emit_rerun_if_changed(&entry_html);
    emit_rerun_if_changed_recursive(&src_dir);
    emit_rerun_if_changed_recursive(&dist_dir);
    emit_git_rerun_hints(&manifest_dir);

    stage_dist(&dist_dir, &staged_dist_dir).expect("failed to stage lite web client assets");
    println!(
        "cargo:rustc-env=AUTHOS_BUILD_VERSION={}",
        resolve_build_version(&manifest_dir)
    );
    println!(
        "cargo:rustc-env=LITE_WEB_DIST_DIR={}",
        staged_dist_dir.display()
    );
}

fn emit_rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn emit_rerun_if_changed_recursive(path: &Path) {
    emit_rerun_if_changed(path);

    if !path.exists() {
        return;
    }

    let mut entries = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("failed to collect {}: {error}", path.display()));

    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            emit_rerun_if_changed_recursive(&entry_path);
        } else {
            emit_rerun_if_changed(&entry_path);
        }
    }
}

fn emit_git_rerun_hints(manifest_dir: &Path) {
    let git_dir = match resolve_git_dir(manifest_dir) {
        Some(path) => path,
        None => return,
    };

    for path in [
        git_dir.join("HEAD"),
        git_dir.join("packed-refs"),
        git_dir.join("refs").join("tags"),
    ] {
        if path.exists() {
            emit_rerun_if_changed(&path);
        }
    }
}

fn resolve_build_version(manifest_dir: &Path) -> String {
    if let Ok(explicit) = env::var("AUTHOS_BUILD_VERSION") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Some(tag) = resolve_exact_git_tag(manifest_dir) {
        return tag;
    }

    let cargo_pkg_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is not set");
    println!(
        "cargo:warning=AUTHOS_BUILD_VERSION was not provided and no exact git tag matched HEAD; falling back to CARGO_PKG_VERSION={cargo_pkg_version}"
    );
    cargo_pkg_version
}

fn resolve_exact_git_tag(manifest_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let tag = String::from_utf8(output.stdout).ok()?;
    let trimmed = tag.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_git_dir(manifest_dir: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let git_dir = String::from_utf8(output.stdout).ok()?;
    let trimmed = git_dir.trim();
    if trimmed.is_empty() {
        return None;
    }

    let path = PathBuf::from(trimmed);
    Some(if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    })
}

fn stage_dist(source_dir: &Path, staged_dir: &Path) -> std::io::Result<()> {
    if staged_dir.exists() {
        fs::remove_dir_all(staged_dir)?;
    }
    fs::create_dir_all(staged_dir)?;

    if source_dir.exists() {
        copy_dir_recursive(source_dir, staged_dir)?;
        return Ok(());
    }

    fs::write(
        staged_dir.join("index.html"),
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AuthOS lite client not built</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 0; background: #0b1020; color: #f7f8fa; }
      main { max-width: 44rem; margin: 4rem auto; padding: 0 1.5rem; }
      code { background: rgba(255,255,255,0.08); padding: 0.15rem 0.35rem; border-radius: 0.25rem; }
      p { line-height: 1.5; color: #c9d1d9; }
    </style>
  </head>
  <body>
    <main>
      <h1>Lite web client assets were not built</h1>
      <p>This binary was compiled without <code>lite-web-client/dist</code>. Build the lite client first with <code>npm --workspace lite-web-client run build</code>, then rebuild AuthOS.</p>
    </main>
  </body>
</html>
"#,
    )?;
    println!("cargo:warning=lite-web-client/dist is missing; embedding a placeholder page instead");
    Ok(())
}

fn copy_dir_recursive(source_dir: &Path, staged_dir: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = staged_dir.join(entry.file_name());

        if source_path.is_dir() {
            fs::create_dir_all(&target_path)?;
            copy_dir_recursive(&source_path, &target_path)?;
        } else {
            fs::copy(&source_path, &target_path)?;
        }
    }

    Ok(())
}
