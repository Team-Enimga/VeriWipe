pub mod detector;
pub mod lab;
pub mod safety;

pub use detector::{list_block_devices, BlockDeviceInfo};
pub use lab::{
    cleanup_synthetic_disks, create_synthetic_disk, list_synthetic_disks, InjectedArtifact,
    LabDiskManifest,
};
pub use safety::{resolve_parent_disk, SystemProtectionInfo};
