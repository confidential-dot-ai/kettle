//! Read the dm-verity root hash stored in a disk image's verity partition.
//!
//! The disk (built by steep/mkosi/systemd-repart) is a GPT image whose
//! `root-verity` partition begins with a 512-byte dm-verity superblock followed
//! by the hash tree. cryptsetup stores the tree's root level immediately after
//! the superblock, so the dm-verity root hash is `H(salt ‖ first_hash_block)` —
//! no data-partition pass or Merkle recomputation is needed.

use std::path::Path;

use fs_err::os::unix::fs::FileExt;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256, Sha512};

const LBA: u64 = 512;
const VERITY_MAGIC: &[u8; 8] = b"verity\0\0";

/// Bytes read from the front of the disk to parse the GPT header and partition
/// table. The protective MBR + header sit at LBA0/LBA1 and a standard table is
/// 128 entries × 128 bytes starting at LBA2, so 64 KiB covers it comfortably.
const HEAD_BYTES: u64 = 64 * 1024;

/// GPT partition type GUID for `root-verity` (x86-64), in GPT on-disk
/// (mixed-endian) byte order: 2c7357ed-ebd2-46d9-aec1-23d437ec2bf5.
const VERITY_TYPE_GUID: [u8; 16] = [
    0xed, 0x57, 0x73, 0x2c, 0xd2, 0xeb, 0xd9, 0x46, 0xae, 0xc1, 0x23, 0xd4, 0x37, 0xec, 0x2b, 0xf5,
];

fn digest_with_salt(algo: &str, salt: &[u8], block: &[u8]) -> Result<String> {
    match algo {
        "sha256" => {
            let mut h = Sha256::new();
            h.update(salt);
            h.update(block);
            Ok(hex::encode(h.finalize()))
        }
        "sha512" => {
            let mut h = Sha512::new();
            h.update(salt);
            h.update(block);
            Ok(hex::encode(h.finalize()))
        }
        other => bail!("unsupported dm-verity hash algorithm: {other}"),
    }
}

/// Given the bytes of a verity partition (superblock at offset 0, hash tree
/// after), compute the dm-verity root hash.
pub fn roothash_from_verity_partition(part: &[u8]) -> Result<String> {
    if part.len() < 4096 || &part[0..8] != VERITY_MAGIC {
        bail!("not a dm-verity partition (bad superblock magic)");
    }
    let version = u32::from_le_bytes(part[8..12].try_into().unwrap());
    if version != 1 {
        bail!("unsupported dm-verity superblock version: {version}");
    }
    // unwrap_or(32): if the 32-byte algorithm field has no NUL terminator, use
    // it whole; digest_with_salt rejects any unknown algorithm name anyway.
    let algo_end = 32 + part[32..64].iter().position(|&b| b == 0).unwrap_or(32);
    let algo = std::str::from_utf8(&part[32..algo_end])
        .context("verity algorithm not UTF-8")?
        .to_string();
    let hash_block_size = u32::from_le_bytes(part[68..72].try_into().unwrap()) as usize;
    let salt_size = u16::from_le_bytes(part[80..82].try_into().unwrap()) as usize;
    if 88 + salt_size > part.len() {
        bail!("verity superblock salt out of range");
    }
    let salt = &part[88..88 + salt_size];
    let root_block = part
        .get(hash_block_size..hash_block_size * 2)
        .context("verity partition too small to hold a root hash block")?;
    digest_with_salt(&algo, salt, root_block)
}

/// Locate the `root-verity` partition in a GPT disk image and return its
/// (byte offset, byte length).
fn find_verity_partition(disk: &[u8]) -> Result<(usize, usize)> {
    let header = disk
        .get(LBA as usize..LBA as usize + 92)
        .context("disk too small for a GPT header")?;
    if &header[0..8] != b"EFI PART" {
        bail!("image is not a GPT disk (no 'EFI PART' header at LBA1)");
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(header[80..84].try_into().unwrap()) as usize;
    let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap()) as usize;
    // A GPT entry holds the type GUID (0..16) plus the start/end LBAs (32..48)
    // we read below; reject a table whose declared entry size can't hold them.
    if entry_size < 48 {
        bail!("GPT partition entry size too small: {entry_size}");
    }

    let mut off = entries_lba as usize * LBA as usize;
    for _ in 0..num_entries {
        let entry = disk
            .get(off..off + entry_size)
            .context("GPT partition entry out of range")?;
        if entry[0..16] == VERITY_TYPE_GUID {
            let first = u64::from_le_bytes(entry[32..40].try_into().unwrap());
            let last = u64::from_le_bytes(entry[40..48].try_into().unwrap());
            if last < first {
                bail!("verity partition has EndingLBA {last} before StartingLBA {first}");
            }
            // Checked arithmetic throughout: first/last come straight from the
            // on-disk GPT entry, so a crafted image must not panic here.
            let lba_count = (last - first)
                .checked_add(1)
                .context("verity partition LBA range overflows u64")?;
            let start = first
                .checked_mul(LBA)
                .and_then(|v| usize::try_from(v).ok())
                .context("verity partition offset overflows")?;
            let len = lba_count
                .checked_mul(LBA)
                .and_then(|v| usize::try_from(v).ok())
                .context("verity partition length overflows")?;
            return Ok((start, len));
        }
        off += entry_size;
    }
    bail!("no root-verity partition found in disk image");
}

/// Read the dm-verity root hash stored in a disk image's verity partition.
///
/// Only the bytes actually needed are read — the GPT header/table from the front
/// of the disk, then the verity partition's superblock and root hash block —
/// rather than slurping the whole (multi-GB) image into memory.
pub fn stored_roothash(image_path: &Path) -> Result<String> {
    let file = fs_err::File::open(image_path)?;

    // Read the front of the disk to locate the verity partition via the GPT.
    let total = file.metadata()?.len();
    let mut head = vec![0u8; total.min(HEAD_BYTES) as usize];
    file.read_exact_at(&mut head, 0)
        .context("reading GPT header from disk image")?;
    let (start, _len) = find_verity_partition(&head)?;
    let start = start as u64;

    // Read the verity partition's superblock (first block) to learn its hash
    // block size, then read the superblock plus the root hash block. The root
    // hash is H(salt ‖ block at hash_block_size), so this is all we need — no
    // need to read the rest of the (tens of MB) hash tree.
    let mut part = vec![0u8; 4096];
    file.read_exact_at(&mut part, start)
        .context("reading verity superblock from disk image")?;
    let hash_block_size = u32::from_le_bytes(
        part[68..72]
            .try_into()
            .context("verity superblock too short for hash block size")?,
    ) as usize;
    let needed = hash_block_size
        .checked_mul(2)
        .context("verity hash block size overflows")?;
    if needed > part.len() {
        part.resize(needed, 0);
        file.read_exact_at(&mut part, start)
            .context("reading verity root hash block from disk image")?;
    }
    roothash_from_verity_partition(&part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A fresh random 32-byte salt. The tests don't care about the value.
    fn random_salt() -> [u8; 32] {
        rand::random()
    }

    /// A verity partition image = 512-byte superblock (padded to 4096) followed
    /// by the root hash block at block 1.
    fn synthetic_verity_partition(salt: &[u8], root_block: &[u8; 4096]) -> Vec<u8> {
        let mut sb = vec![0u8; 4096];
        sb[0..8].copy_from_slice(b"verity\0\0");
        sb[8..12].copy_from_slice(&1u32.to_le_bytes()); // version
        sb[12..16].copy_from_slice(&1u32.to_le_bytes()); // hash_type
        sb[32..38].copy_from_slice(b"sha256");
        sb[64..68].copy_from_slice(&4096u32.to_le_bytes()); // data_block_size
        sb[68..72].copy_from_slice(&4096u32.to_le_bytes()); // hash_block_size
        sb[72..80].copy_from_slice(&1u64.to_le_bytes()); // data_blocks
        sb[80..82].copy_from_slice(&(salt.len() as u16).to_le_bytes());
        sb[88..88 + salt.len()].copy_from_slice(salt);
        let mut out = sb;
        out.extend_from_slice(root_block);
        out
    }

    #[test]
    fn roothash_from_verity_matches_hand_computed() {
        let salt = random_salt();
        let mut root_block = [0u8; 4096];
        root_block[..4].copy_from_slice(b"root");
        let part = synthetic_verity_partition(&salt, &root_block);

        let got = roothash_from_verity_partition(&part).unwrap();

        let mut h = Sha256::new();
        h.update(salt);
        h.update(root_block);
        assert_eq!(got, hex::encode(h.finalize()));
    }

    #[test]
    fn roothash_rejects_bad_magic() {
        let mut part = synthetic_verity_partition(&random_salt(), &[0u8; 4096]);
        part[0] = b'X';
        assert!(roothash_from_verity_partition(&part).is_err());
    }

    /// Minimal GPT (512-byte LBA): protective space + header @ LBA1 + one
    /// partition entry pointing at a verity partition placed at `verity_lba`.
    fn synthetic_disk(verity_lba: u64, verity_bytes: &[u8]) -> Vec<u8> {
        let entries_lba = 2u64;
        let part_lba = verity_lba;
        let total = (part_lba as usize + verity_bytes.len().div_ceil(512) + 1) * 512;
        let mut disk = vec![0u8; total.max(part_lba as usize * 512 + verity_bytes.len())];

        // GPT header @ LBA1
        let h = 512;
        disk[h..h + 8].copy_from_slice(b"EFI PART");
        disk[h + 72..h + 80].copy_from_slice(&entries_lba.to_le_bytes()); // PartitionEntryLBA
        disk[h + 80..h + 84].copy_from_slice(&1u32.to_le_bytes()); // NumberOfPartitionEntries
        disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // SizeOfPartitionEntry

        // one entry @ entries_lba
        let e = entries_lba as usize * 512;
        disk[e..e + 16].copy_from_slice(&VERITY_TYPE_GUID); // PartitionTypeGUID
        disk[e + 32..e + 40].copy_from_slice(&part_lba.to_le_bytes()); // StartingLBA
        let end_lba = part_lba + verity_bytes.len().div_ceil(512) as u64 - 1;
        disk[e + 40..e + 48].copy_from_slice(&end_lba.to_le_bytes()); // EndingLBA

        // verity partition bytes
        let p = part_lba as usize * 512;
        disk[p..p + verity_bytes.len()].copy_from_slice(verity_bytes);
        disk
    }

    #[test]
    fn stored_roothash_finds_verity_partition() {
        let salt = random_salt();
        let mut root_block = [0u8; 4096];
        root_block[..5].copy_from_slice(b"hello");
        let part = synthetic_verity_partition(&salt, &root_block);
        let disk = synthetic_disk(40, &part);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("disk.raw");
        fs_err::write(&path, &disk).unwrap();

        let got = stored_roothash(&path).unwrap();
        let expected = roothash_from_verity_partition(&part).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn stored_roothash_does_not_require_full_hash_tree() {
        // A real verity partition declares its full length (the whole hash
        // tree, tens of MB), but only the superblock + root hash block are
        // needed to read the stored root hash. stored_roothash must succeed
        // even when the file ends right after the root block — i.e. it must
        // not depend on the entire declared partition being present/read.
        let salt = random_salt();
        let mut root_block = [0u8; 4096];
        root_block[..3].copy_from_slice(b"abc");
        let part = synthetic_verity_partition(&salt, &root_block); // 8192 bytes

        // Place verity far into the disk, declare it spanning ~51 MB, but only
        // write the 8192 bytes that actually hold the superblock + root block.
        let entries_lba = 2u64;
        let part_lba = 2048u64;
        let declared_end_lba = part_lba + 100_000 - 1;

        let file_len = part_lba as usize * 512 + part.len();
        let mut disk = vec![0u8; file_len];
        let h = 512;
        disk[h..h + 8].copy_from_slice(b"EFI PART");
        disk[h + 72..h + 80].copy_from_slice(&entries_lba.to_le_bytes());
        disk[h + 80..h + 84].copy_from_slice(&1u32.to_le_bytes());
        disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
        let e = entries_lba as usize * 512;
        disk[e..e + 16].copy_from_slice(&VERITY_TYPE_GUID);
        disk[e + 32..e + 40].copy_from_slice(&part_lba.to_le_bytes());
        disk[e + 40..e + 48].copy_from_slice(&declared_end_lba.to_le_bytes());
        let p = part_lba as usize * 512;
        disk[p..p + part.len()].copy_from_slice(&part);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("disk.raw");
        fs_err::write(&path, &disk).unwrap();

        let got = stored_roothash(&path).unwrap();
        let expected = roothash_from_verity_partition(&part).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn find_verity_rejects_tiny_entry_size() {
        // A GPT whose declared SizeOfPartitionEntry can't hold the fields we
        // read must error, not panic.
        let mut disk = vec![0u8; 4096];
        disk[512..520].copy_from_slice(b"EFI PART");
        disk[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes()); // PartitionEntryLBA
        disk[512 + 80..512 + 84].copy_from_slice(&1u32.to_le_bytes()); // NumberOfPartitionEntries
        disk[512 + 84..512 + 88].copy_from_slice(&8u32.to_le_bytes()); // SizeOfPartitionEntry (too small)
        assert!(find_verity_partition(&disk).is_err());
    }

    #[test]
    fn stored_roothash_handles_partition_start_beyond_disk() {
        // A verity entry whose StartingLBA points past the end of the file must
        // error, not panic (no usize underflow).
        let part = synthetic_verity_partition(&random_salt(), &[0u8; 4096]);
        let mut disk = synthetic_disk(40, &part);
        // Rewrite the entry's StartingLBA to a wildly out-of-range value.
        let e = 2 * 512;
        disk[e + 32..e + 40].copy_from_slice(&1_000_000u64.to_le_bytes());

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("disk.raw");
        fs_err::write(&path, &disk).unwrap();
        assert!(stored_roothash(&path).is_err());
    }

    #[test]
    fn find_verity_rejects_overflowing_lba_range() {
        // EndingLBA = u64::MAX, StartingLBA = 0: last+1 would overflow. Must
        // error, not panic.
        let part = synthetic_verity_partition(&random_salt(), &[0u8; 4096]);
        let mut disk = synthetic_disk(40, &part);
        let e = 2 * 512;
        disk[e + 32..e + 40].copy_from_slice(&0u64.to_le_bytes()); // StartingLBA
        disk[e + 40..e + 48].copy_from_slice(&u64::MAX.to_le_bytes()); // EndingLBA
        assert!(find_verity_partition(&disk).is_err());
    }

    #[test]
    #[ignore = "requires local steep build at /home/ubuntu/steep/output/base"]
    fn stored_roothash_from_real_disk() {
        let got = stored_roothash(Path::new("/home/ubuntu/steep/output/base/disk.raw")).unwrap();
        assert_eq!(
            got,
            "695be9124b1f2043c8ea1e248a98792cf003002b95610061d5b27de0c77ea741"
        );
    }
}
