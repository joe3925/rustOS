use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug)]
pub struct KernelArtifact {
    pub pe: PathBuf,
    pub debug_info: Option<PathBuf>,
}

#[derive(Debug)]
pub struct KernelSdkArtifact {
    pub definition_file: PathBuf,
    pub import_library: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DriverPackageArtifact {
    pub name: String,
    pub configuration: PathBuf,
    pub binary: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<PathBuf>,
    pub source: DriverProvenance,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DriverProvenance {
    LocalCargo {
        manifest: PathBuf,
    },
    LocalFiles,
    GitCargo {
        repository: String,
        revision: String,
        manifest: PathBuf,
    },
}

#[derive(Debug)]
pub struct StubArtifact {
    pub executable: PathBuf,
}

#[derive(Debug)]
pub struct BootArtifact {
    pub image: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ArtifactManifest {
    pub schema: u32,
    pub platform: String,
    pub profile: String,
    pub kernel: PublishedKernel,
    pub sdk: PublishedSdk,
    pub stub: PathBuf,
    pub boot_image: PathBuf,
    pub boot_packages: Vec<DriverPackageArtifact>,
    pub debug_search_paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublishedSdk {
    pub definition_file: PathBuf,
    pub import_library: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublishedKernel {
    pub image: PathBuf,
    pub debug: Option<PathBuf>,
}
