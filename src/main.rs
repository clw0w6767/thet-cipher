//! THET v21 - Rust implementation

mod crypto;
mod hardened_io;

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::exit;

use crypto::*;
use hardened_io::*;

const CHUNK: usize = 1024 * 1024;

fn read_exact_at(f: &mut File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn do_encrypt(src: &Path, dst: &Path) -> Result<(), String> {
    let password = load_password()?;

    let mut in_f = File::open(src).map_err(|e| format!("open {src:?}: {e}"))?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let master = derive_master(&password, &salt)?;
    let keys = derive_keys(&master, &salt);
    let (n1, n2, n3) = derive_stream_nonces(&keys.nonce_key, &nonce);

    let mut out_f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| format!("create {dst:?}: {e}"))?;

    out_f.write_all(&salt).map_err(|e| e.to_string())?;
    out_f.write_all(&nonce).map_err(|e| e.to_string())?;

    let ad = encode_ad(&[LBL_MAC1, LBL_MAC2, &salt, &nonce]);
    let mut mac = DualMac::new(&keys, &ad);

    let mut offset: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = in_f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        let ks = keystream_at(&keys, &n1, &n2, &n3, offset, n);
        let ct: Vec<u8> = buf[..n].iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        out_f.write_all(&ct).map_err(|e| e.to_string())?;
        mac.update(&ct);
        offset += n as u64;
    }

    let (m1, m2) = mac.finalize();
    out_f.write_all(&m1).map_err(|e| e.to_string())?;
    out_f.write_all(&m2).map_err(|e| e.to_string())?;
    out_f.sync_all().map_err(|e| e.to_string())?;

    println!("[+] Encrypted: {} -> {} ({} bytes)", src.display(), dst.display(), offset);
    Ok(())
}

fn do_decrypt(src: &Path, dst: &Path) -> Result<(), String> {
    let password = load_password()?;

    let dst_dir = dst.parent().unwrap_or_else(|| Path::new("."));
    if !dst_dir.is_dir() {
        return Err(format!("destination directory not found: {}", dst_dir.display()));
    }

    let (mut f, fp_before) = open_locked(src).map_err(|e| format!("open_locked: {e}"))?;
    let fd = f.as_raw_fd();

    let total = f.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let min_len = (SALT_LEN + NONCE_LEN + 2 * MAC_LEN) as u64;
    if total < min_len {
        unlock(fd);
        return Err("ciphertext too short".into());
    }
    let body_len = total - min_len;

    let header = read_exact_at(&mut f, 0, SALT_LEN + NONCE_LEN).map_err(|e| e.to_string())?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    salt.copy_from_slice(&header[..SALT_LEN]);
    nonce.copy_from_slice(&header[SALT_LEN..]);

    let tail = read_exact_at(&mut f, total - 2 * MAC_LEN as u64, 2 * MAC_LEN)
        .map_err(|e| e.to_string())?;
    let mut mac1_stored = [0u8; MAC_LEN];
    let mut mac2_stored = [0u8; MAC_LEN];
    mac1_stored.copy_from_slice(&tail[..MAC_LEN]);
    mac2_stored.copy_from_slice(&tail[MAC_LEN..]);

    let master = derive_master(&password, &salt)?;
    let keys = derive_keys(&master, &salt);
    let (n1, n2, n3) = derive_stream_nonces(&keys.nonce_key, &nonce);

    let ad = encode_ad(&[LBL_MAC1, LBL_MAC2, &salt, &nonce]);
    let mut mac = DualMac::new(&keys, &ad);

    f.seek(SeekFrom::Start((SALT_LEN + NONCE_LEN) as u64))
        .map_err(|e| e.to_string())?;
    let mut remaining = body_len;
    let mut buf = vec![0u8; CHUNK];
    while remaining > 0 {
        let to_read = std::cmp::min(CHUNK as u64, remaining) as usize;
        f.read_exact(&mut buf[..to_read]).map_err(|e| e.to_string())?;
        mac.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }

    let (m1, m2) = mac.finalize();
    if !ct_eq(&m1, &mac1_stored) || !ct_eq(&m2, &mac2_stored) {
        unlock(fd);
        return Err("integrity check failed: ciphertext tampered or wrong password".into());
    }

    let fp_after = fingerprint(fd).map_err(|e| e.to_string())?;
    if fp_before != fp_after {
        unlock(fd);
        return Err("input file changed during MAC verification, refusing to decrypt".into());
    }

    let tmp_path = dst_dir.join(format!(
        ".thet21_tmp_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut out_f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("create tmp: {e}"))?;

    f.seek(SeekFrom::Start((SALT_LEN + NONCE_LEN) as u64))
        .map_err(|e| e.to_string())?;
    remaining = body_len;
    let mut offset: u64 = 0;
    while remaining > 0 {
        let to_read = std::cmp::min(CHUNK as u64, remaining) as usize;
        f.read_exact(&mut buf[..to_read]).map_err(|e| e.to_string())?;
        let ks = keystream_at(&keys, &n1, &n2, &n3, offset, to_read);
        let pt: Vec<u8> = buf[..to_read].iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        out_f.write_all(&pt).map_err(|e| e.to_string())?;
        offset += to_read as u64;
        remaining -= to_read as u64;
    }
    out_f.sync_all().map_err(|e| e.to_string())?;
    drop(out_f);

    let fp_final = fingerprint(fd).map_err(|e| e.to_string())?;
    if fp_before != fp_final {
        let _ = std::fs::remove_file(&tmp_path);
        unlock(fd);
        return Err("input file changed during decryption, refusing to output".into());
    }

    atomic_rename_noreplace(&tmp_path, dst)
        .map_err(|e| format!("atomic rename failed: {e}"))?;

    unlock(fd);

    println!("[+] Decrypted: {} -> {} ({} bytes)", src.display(), dst.display(), body_len);
    Ok(())
}

fn load_password() -> Result<Vec<u8>, String> {
    use std::io::BufRead;
    if let Ok(pw) = std::env::var("THET_PASSPHRASE") {
        return Ok(pw.into_bytes());
    }
    eprint!("[THET v21] Passphrase: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line.into_bytes())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage:");
        eprintln!("  {} encrypt <input> <output.thet21>", args[0]);
        eprintln!("  {} decrypt <input.thet21> <output>", args[0]);
        exit(1);
    }
    let cmd = &args[1];
    let src = PathBuf::from(&args[2]);
    let dst = PathBuf::from(&args[3]);

    let result = match cmd.as_str() {
        "encrypt" => do_encrypt(&src, &dst),
        "decrypt" => do_decrypt(&src, &dst),
        _ => Err(format!("unknown command: {cmd}")),
    };

    if let Err(e) = result {
        eprintln!("[!] {e}");
        exit(1);
    }
}
