use rea_application::javascript::contracts::semantic_ir::SemanticIr;
use rea_application::javascript::parser::RawDiagnostic;
use rea_application::javascript::semantic::{
    analysis::analyze_source_with_mode, state::ResolutionMode,
};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

#[derive(Deserialize)]
struct Entry {
    id: String,
    file: String,
    path: String,
}

#[derive(Serialize)]
struct ParsedResult<'a> {
    id: &'a str,
    status: &'static str,
    ir: &'a SemanticIr,
}

#[derive(Serialize)]
struct FatalResult {
    id: String,
    status: &'static str,
    diagnostics: Vec<DiagnosticResult>,
}

#[derive(Serialize)]
struct DiagnosticResult {
    message: String,
    byte_offset: Option<u32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mode = resolution_mode(env::var("SEM_MODE").ok().as_deref())?;

    if args.get(1).map(String::as_str) == Some("-e") {
        let source = args.get(2).ok_or("missing source")?;
        let path = args.get(3).map(String::as_str).unwrap_or("probe.js");
        write_result("probe", source, path, mode)?;
        return Ok(());
    }

    let manifest_path = PathBuf::from(args.get(1).ok_or("missing manifest")?);
    let output_path = PathBuf::from(args.get(2).ok_or("missing output")?);
    let entries: Vec<Entry> = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
    let manifest_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut output = fs::File::create(output_path)?;

    for entry in entries {
        let source = fs::read_to_string(manifest_dir.join(&entry.file))?;
        write_entry(&mut output, &entry.id, &source, &entry.path, mode)?;
    }

    Ok(())
}

fn write_result(
    id: &str,
    source: &str,
    path: &str,
    mode: ResolutionMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_entry(&mut output, id, source, path, mode)?;
    output.flush()?;
    Ok(())
}

fn write_entry(
    output: &mut impl Write,
    id: &str,
    source: &str,
    path: &str,
    mode: ResolutionMode,
) -> Result<(), Box<dyn std::error::Error>> {
    match analyze_source_with_mode(source, Some(path), mode) {
        Ok(ir) => {
            verify_ir_roundtrip(&ir)?;
            writeln!(
                output,
                "{}",
                serde_json::to_string(&ParsedResult {
                    id,
                    status: "parsed",
                    ir: &ir,
                })?
            )?;
        }
        Err(diagnostics) => {
            writeln!(
                output,
                "{}",
                serde_json::to_string(&FatalResult {
                    id: id.to_owned(),
                    status: "fatal",
                    diagnostics: diagnostics.into_iter().map(diagnostic_result).collect(),
                })?
            )?;
        }
    }

    Ok(())
}

fn verify_ir_roundtrip(ir: &SemanticIr) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = serde_json::to_string(ir)?;
    let decoded: SemanticIr = serde_json::from_str(&encoded)?;
    let reencoded = serde_json::to_string(&decoded)?;
    if encoded != reencoded {
        return Err("SemanticIr JSON changed after deserialize/serialize roundtrip".into());
    }
    Ok(())
}

fn diagnostic_result(diagnostic: RawDiagnostic) -> DiagnosticResult {
    DiagnosticResult {
        message: diagnostic.message,
        byte_offset: diagnostic.byte_offset,
    }
}

fn resolution_mode(value: Option<&str>) -> Result<ResolutionMode, Box<dyn std::error::Error>> {
    match value.unwrap_or("import") {
        "import" => Ok(ResolutionMode::Import),
        "require" => Ok(ResolutionMode::Require),
        "compiler-dependent" => Ok(ResolutionMode::CompilerDependent),
        other => Err(format!("unsupported SEM_MODE {other:?}").into()),
    }
}
