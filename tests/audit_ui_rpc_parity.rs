//! Rust の監査UI RPC クライアントが呼ぶ RPC が、Supabase migration に定義されているかを検証する。
//!
//! 背景: src/server/supabase/audit_ui_rpc.rs の post_rpc("rpc_audit_ui_*", ...) が呼ぶ RPC が
//! migration に未定義のまま出荷され、PostgREST が PGRST202 (404) を返す不整合が発生していた
//! (Section 1370 で修正)。このテストは Rust↔SQL の境界を静的に検査し、同種の不整合の再発を防ぐ。

use std::fs;
use std::path::{Path, PathBuf};

const AUDIT_UI_RPC_SOURCE: &str = "src/server/supabase/audit_ui_rpc.rs";
const MIGRATIONS_DIR: &str = "supabase/migrations";

#[test]
fn audit_ui_rpc_names_are_defined_in_migrations() {
    let source = fs::read_to_string(AUDIT_UI_RPC_SOURCE)
        .unwrap_or_else(|error| panic!("{AUDIT_UI_RPC_SOURCE} should be readable: {error}"));
    let rpc_names = extract_post_rpc_names(&source);

    assert!(
        !rpc_names.is_empty(),
        "expected to find post_rpc(...) calls in {AUDIT_UI_RPC_SOURCE}"
    );

    let migrations = read_all_migrations();

    let missing: Vec<&String> = rpc_names
        .iter()
        .filter(|name| !migrations.contains(&format!("function public.{name}(")))
        .collect();

    assert!(
        missing.is_empty(),
        "RPCs called from {AUDIT_UI_RPC_SOURCE} but not defined in {MIGRATIONS_DIR}: {missing:?}"
    );
}

/// `post_rpc(` 呼び出しの第1引数 (RPC 名の文字列リテラル) をすべて抽出する。
/// 引数が改行で折り返されているケース (例: post_rpc(\n "rpc_x",\n ...)) にも対応する。
fn extract_post_rpc_names(source: &str) -> Vec<String> {
    const NEEDLE: &str = "post_rpc(";
    let mut names = Vec::new();
    let mut cursor = 0;

    while let Some(rel) = source[cursor..].find(NEEDLE) {
        let after_call = cursor + rel + NEEDLE.len();

        // post_rpc( の直後で最初に現れる文字列リテラルが RPC 名。
        let Some(open_rel) = source[after_call..].find('"') else {
            break;
        };
        let name_start = after_call + open_rel + 1;
        let Some(close_rel) = source[name_start..].find('"') else {
            break;
        };
        let name_end = name_start + close_rel;

        names.push(source[name_start..name_end].to_owned());
        cursor = name_end + 1;
    }

    names
}

/// supabase/migrations 配下の全 .sql を連結して返す。
fn read_all_migrations() -> String {
    let mut paths: Vec<PathBuf> = fs::read_dir(Path::new(MIGRATIONS_DIR))
        .unwrap_or_else(|error| panic!("{MIGRATIONS_DIR} should be readable: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("migration dir entry should be readable: {error}"))
                .path()
        })
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    paths.sort();

    let mut combined = String::new();
    for path in paths {
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()));
        combined.push_str(&content);
        combined.push('\n');
    }
    combined
}
