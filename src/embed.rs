//! Resolve a frontend build once during compilation. Requests only consult the generated table.
use anyhow::{Context, Result, bail};
use std::path::{Component, Path, PathBuf};

pub fn assets(base: &Path, dir: &str) -> Result<Vec<(String, PathBuf)>> {
    let base = base.canonicalize()?;
    let mut root = base;
    if dir.is_empty() || !Path::new(dir).components().any(|c| matches!(c, Component::Normal(_))) {
        bail!("@embed_dir needs a build subdirectory");
    }
    for component in Path::new(dir).components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => root.push(part),
            _ => bail!("@embed_dir needs a project-relative path"),
        }
        if root.symlink_metadata()?.is_symlink() {
            bail!("symlink in @embed_dir path");
        }
    }
    let mut dirs = vec![root.clone()];
    let mut files = Vec::new();
    while let Some(parent) = dirs.pop() {
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let path = entry.path();
            if ty.is_dir() {
                dirs.push(path);
            } else if ty.is_file() {
                let rel = path.strip_prefix(&root)?.to_str().context("non-UTF-8 asset name")?;
                files.push((format!("/{}", rel.replace(std::path::MAIN_SEPARATOR, "/")), path));
            } else {
                bail!("expected a regular asset file at {}", path.display());
            }
        }
    }
    files.sort();
    if !files.iter().any(|(url, _)| url == "/index.html") {
        bail!("@embed_dir requires index.html");
    }
    Ok(files)
}

pub fn mime(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map_or("", |(_, ext)| ext);
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "cjs" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "png" => "image/png",
        "gif" => "image/gif",
        "avif" => "image/avif",
        "webp" => "image/webp",
        "jpg" | "jpeg" => "image/jpeg",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embed_requires_a_relative_build_and_index() {
        for path in ["", ".", "..", "/tmp"] {
            assert!(assets(Path::new("."), path).is_err());
        }
        assert_eq!(mime("dist/main.JS"), "text/javascript; charset=utf-8");
        assert_eq!(mime("dist/file.bin"), "application/octet-stream");
    }
}
