//! Which source files are test-only as a whole.
//!
//! Inline `#[cfg(test)]` items are skipped while the model is built, but most
//! Soroban crates keep their tests in separate files: `#[cfg(test)] mod test;`
//! pulls in `src/test.rs`, and integration tests, benches and fuzz targets live
//! under `tests/`, `benches/` and `fuzz/`. Nothing inside those files carries a
//! test attribute, so they are identified here, before the model is built.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use syn::Item;

use crate::source::{FileId, SourceMap};
use crate::syntax::attrs::is_test;

/// Directory names whose contents are never deployed contract code.
const TEST_DIRS: &[&str] = &["tests", "benches", "fuzz"];

/// Files that contain only test code.
pub(crate) fn test_only_files(sources: &SourceMap) -> HashSet<FileId> {
    // Paths declared by `#[cfg(test)] mod name;` — a file, or a directory whose
    // whole subtree belongs to the test module.
    let mut test_modules: Vec<PathBuf> = Vec::new();
    for source in sources.iter() {
        let path = source.path();
        let Some(parent) = path.parent() else {
            continue;
        };
        let owns_dir = matches!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some("lib" | "main" | "mod")
        );
        let dir = match path.file_stem() {
            Some(stem) if !owns_dir => parent.join(stem),
            _ => parent.to_path_buf(),
        };
        collect_test_modules(&source.syntax().items, parent, &dir, &mut test_modules);
    }

    sources
        .iter()
        .filter(|source| {
            let path = source.path();
            is_test_path(Path::new(source.display_path()))
                || test_modules
                    .iter()
                    .any(|module| path == module || path.starts_with(module))
        })
        .map(|source| source.id())
        .collect()
}

/// Walk `items` (declared in a file whose child modules live in `dir`) for
/// out-of-line test modules.
fn collect_test_modules(items: &[Item], file_dir: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    for item in items {
        let Item::Mod(module) = item else {
            continue;
        };
        let name = module.ident.to_string();
        if is_test(&module.attrs) {
            if let Some(explicit) = path_attr(&module.attrs) {
                out.push(file_dir.join(explicit));
            } else {
                out.push(dir.join(format!("{name}.rs")));
                out.push(dir.join(&name));
            }
        } else if let Some((_, nested)) = &module.content {
            collect_test_modules(nested, file_dir, &dir.join(&name), out);
        }
    }
}

/// The value of a `#[path = "..."]` attribute.
fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        match &attr.meta {
            syn::Meta::NameValue(syn::MetaNameValue {
                value:
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(value),
                        ..
                    }),
                ..
            }) => Some(value.value()),
            _ => None,
        }
    })
}

/// Whether a project-relative path is test code by Cargo convention or name.
fn is_test_path(path: &Path) -> bool {
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let name = component.as_os_str().to_string_lossy();
        if components.peek().is_some() {
            if TEST_DIRS.contains(&name.as_ref()) {
                return true;
            }
            continue;
        }
        let stem = name.strip_suffix(".rs").unwrap_or(&name);
        return matches!(stem, "test" | "tests")
            || stem.starts_with("test_")
            || stem.ends_with("_test")
            || stem.ends_with("_tests");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceFile;

    fn map(files: &[(&str, &str)]) -> SourceMap {
        let files = files
            .iter()
            .enumerate()
            .map(|(index, (path, text))| {
                SourceFile::parse(FileId(index as u32), path, *path, *text).unwrap()
            })
            .collect();
        SourceMap::new(files)
    }

    fn test_paths(files: &[(&str, &str)]) -> Vec<String> {
        let sources = map(files);
        let ids = test_only_files(&sources);
        let mut paths: Vec<String> = sources
            .iter()
            .filter(|source| ids.contains(&source.id()))
            .map(|source| source.display_path().to_string())
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn cargo_test_directories_and_names_are_test_code() {
        assert!(is_test_path(Path::new("tests/integration.rs")));
        assert!(is_test_path(Path::new("pool/tests/common/mod.rs")));
        assert!(is_test_path(Path::new("fuzz/fuzz_targets/a.rs")));
        assert!(is_test_path(Path::new("benches/cost.rs")));
        assert!(is_test_path(Path::new("src/test.rs")));
        assert!(is_test_path(Path::new("src/pool_test.rs")));
        assert!(is_test_path(Path::new("src/test_helpers.rs")));
        assert!(!is_test_path(Path::new("src/lib.rs")));
        assert!(!is_test_path(Path::new("src/testament.rs")));
        assert!(!is_test_path(Path::new("src/contest.rs")));
        // A directory named like a test file is not itself a test directory.
        assert!(!is_test_path(Path::new("test/src/lib.rs")));
    }

    #[test]
    fn cfg_test_module_declarations_mark_their_files() {
        let paths = test_paths(&[
            ("src/lib.rs", "#[cfg(test)]\nmod checks;\nmod pool;\n"),
            ("src/checks.rs", "fn a() {}"),
            ("src/pool.rs", "#[cfg(test)]\nmod scenarios;\n"),
            ("src/pool/scenarios/mod.rs", "mod deep;"),
            ("src/pool/scenarios/deep.rs", "fn b() {}"),
            ("src/storage.rs", "fn c() {}"),
        ]);
        assert_eq!(
            paths,
            [
                "src/checks.rs",
                "src/pool/scenarios/deep.rs",
                "src/pool/scenarios/mod.rs"
            ]
        );
    }

    #[test]
    fn path_attributes_and_inline_parents_are_followed() {
        let paths = test_paths(&[
            (
                "src/lib.rs",
                "#[cfg(test)]\n#[path = \"suite.rs\"]\nmod t;\nmod inner { #[cfg(test)] mod checks; }\n",
            ),
            ("src/suite.rs", ""),
            ("src/inner/checks.rs", ""),
            ("src/inner.rs", ""),
        ]);
        assert_eq!(paths, ["src/inner/checks.rs", "src/suite.rs"]);
    }

    #[test]
    fn production_only_modules_stay_in() {
        let paths = test_paths(&[
            ("src/lib.rs", "#[cfg(not(test))]\nmod live;\n"),
            ("src/live.rs", ""),
        ]);
        assert!(paths.is_empty());
    }
}
