use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let workspace_dir = PathBuf::from("../lite-web-client");
    let dist_dir = workspace_dir.join("dist");
    let src_dir = workspace_dir.join("src");
    let package_json = workspace_dir.join("package.json");
    let vite_config = workspace_dir.join("vite.config.js");
    let entry_html = workspace_dir.join("index.html");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let staged_dist_dir = out_dir.join("lite-web-dist");

    for path in [&dist_dir, &src_dir, &package_json, &vite_config, &entry_html] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    stage_dist(&dist_dir, &staged_dist_dir).expect("failed to stage lite web client assets");
    println!("cargo:rustc-env=LITE_WEB_DIST_DIR={}", staged_dist_dir.display());
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
    println!(
        "cargo:warning=lite-web-client/dist is missing; embedding a placeholder page instead"
    );
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
