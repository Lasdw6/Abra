//! A small signed application checkpoint for testing across real CPU architectures.
//! The example materializes files only; run the restored Python program explicitly.
use abra_core::{
    cas::{materialize, snapshot_dir, BlobStore},
    identity::{Identity, Signature},
    manifest::{Manifest, Origin, RawManifest, Scope},
    restore::{plan_restore, RestoreMode},
};
use serde_json::json;
use std::{env, fs, path::Path};

const RESUME: &str = "import json\nfrom pathlib import Path\np = Path(__file__).with_name('checkpoint.json')\ns = json.loads(p.read_text())\ns['completed_steps'] += 1\np.write_text(json.dumps(s) + '\\n')\nprint(json.dumps(s))\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, fixture] if command == "capture" => capture(Path::new(fixture)),
        [command, fixture, destination] if command == "restore" => restore(Path::new(fixture), Path::new(destination), false),
        [command, fixture, destination, flag] if command == "restore" && flag == "--require-arch-change" => restore(Path::new(fixture), Path::new(destination), true),
        _ => Err("usage: portable_checkpoint capture <fixture-dir> | restore <fixture-dir> <new-workspace> [--require-arch-change]".into()),
    }
}

fn capture(fixture: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(fixture)?;
    let workspace = fixture.join("source");
    fs::create_dir(&workspace)?;
    fs::write(
        workspace.join("checkpoint.json"),
        b"{\"completed_steps\":7}\n",
    )?;
    fs::write(workspace.join("resume.py"), RESUME)?;
    let cas = BlobStore::open(fixture)?;
    let identity = Identity::generate();
    let mut manifest = Manifest {
        spec: abra_core::SPEC.into(),
        scope: Scope::Partial,
        kind: "dev.abra.example.checkpoint".into(),
        title: "Portable application checkpoint".into(),
        origin: Origin {
            peer_id: identity.peer_id(),
            name: None,
            adapter: None,
        },
        created_at: "2026-09-06T00:00:00.000Z".into(),
        summary: None,
        link: None,
        thumbnail: None,
        capsule_id: None,
        parents: None,
        labels: None,
        provenance: None,
        files: Some(snapshot_dir(&cas, &workspace)?),
        recipes: None,
        native: None,
        payload: json!({"capture_arch":env::consts::ARCH,"capture_os":env::consts::OS})
            .as_object()
            .unwrap()
            .clone(),
        extensions: None,
        signature: Signature::from_bytes([0; 64]),
    };
    manifest.sign(&identity)?;
    fs::write(
        fixture.join("snapshot.cjson"),
        manifest.to_canonical_bytes()?,
    )?;
    fs::remove_dir_all(workspace)?;
    println!(
        "{}",
        json!({"snapshot_id":manifest.snapshot_id()?,"capture_arch":env::consts::ARCH})
    );
    Ok(())
}

fn restore(
    fixture: &Path,
    destination: &Path,
    require_arch_change: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = RawManifest::parse(fs::read(fixture.join("snapshot.cjson"))?)?;
    let source_arch = raw
        .manifest()
        .payload
        .get("capture_arch")
        .and_then(|value| value.as_str())
        .ok_or("fixture lacks source architecture")?;
    if require_arch_change && source_arch == env::consts::ARCH {
        return Err("this check requires different capture and restore CPU architectures".into());
    }
    let cas = BlobStore::open(fixture)?;
    let plan = plan_restore(&cas, &raw, None, &[])?;
    if plan.mode != RestoreMode::Portable {
        return Err("fixture does not have a complete portable checkpoint".into());
    }
    fs::create_dir(destination)?;
    materialize(
        &cas,
        &plan.portable.files.ok_or("fixture lacks files")?,
        destination,
    )?;
    println!(
        "{}",
        json!({"capture_arch":source_arch,"restore_arch":env::consts::ARCH,"plan":plan})
    );
    Ok(())
}
