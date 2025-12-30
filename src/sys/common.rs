use anyhow::{Result, anyhow};
use colorize::AnsiColor;
use crossterm::{
    event::{Event, KeyCode, KeyModifiers, read},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use serde::Deserialize;
use walkdir::WalkDir;
use std::{
    env,
    fs::{self, File},
    io::{Cursor, Write, stdout},
    path::Path,
};
use zip::ZipArchive;

use crate::{
    console_log,
    sys::{
        filter::{FilterDecision, NovFilter},
        mk::{CachedPassword, MasterVaultKey, WrappedKey},
        process::{
            add_remote_origin, git_add_all, git_add_commit_push, git_branch_main, git_clone, git_commit_all, git_push_origin
        },
        statefile::StateFile,
        writer::{VaultWriter, decrypt},
    },
};

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NovState {
    Uninit,
    Init,
    Sealed,
    Unsealed,
}

/// Checks if there is an existing metadata directory at the
/// target location.
pub fn exists_metadata_directory(root: impl AsRef<Path>) -> bool {
    root.as_ref().join(".nov").exists()
}

/// Checks if a git repo exists at the target location.
pub fn exists_git_repo(root: impl AsRef<Path>) -> bool {
    root.as_ref().join(".git").exists()
}

/// Creates a Git repository at the location.
pub fn make_git_repo(root: impl AsRef<Path>) -> Result<()> {
    use std::process;
    process::Command::new("git")
        .args(vec![
            "init".to_string(),
            root.as_ref().to_str().unwrap().to_string(),
        ])
        .output()?;
    Ok(())
}

fn recreate_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        // Create the folder.
        std::fs::create_dir_all(path)?;
    } else {
        std::fs::remove_dir_all(path)?;
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// This perfoms a seal without performing the directory migrations with the github.
pub fn seal_postmigrate(root: impl AsRef<Path>, master: &MasterVaultKey) -> Result<()> {
    // Do a check to make sure the directory is wellformed.
    let path = root.as_ref();
    if !exists_metadata_directory(&path) {
        return Err(anyhow!("No metadata directory, cannot seal the target."));
    }

    let unsecure_path = path.join(".nov").join("unsecure");
    recreate_dir(&unsecure_path)?;

    let secure_local_path = path.join(".nov").join("secure_local");
    recreate_dir(&secure_local_path)?;

    // Parse in the filter.
    let filter = NovFilter::from_root(path)?;

    let zip_loc = path.join(".nov").join("inpro.bin");
    if zip_loc.exists() {
        std::fs::remove_file(&zip_loc)?;
        console_log!(Info, "Removed the in-progress ZIP file.");
    }

    let secure_local_zip = path.join(".nov").join("secure_local").join("inpro.bin");
    if secure_local_zip.exists() {
        std::fs::remove_file(&secure_local_zip)?;
        console_log!(Info, "Removed the in-progress ZIP file.");
    }



    let mut sec_local_writer = VaultWriter::new(&secure_local_zip, &master.key_bytes())?;

    let mut enc_writer = VaultWriter::new(&zip_loc, &master.key_bytes())?;



    let src_dir = path.canonicalize()?;

    let walk = walkdir::WalkDir::new(&src_dir);

    let mut to_unlink = vec![];

    for file in walk.into_iter().filter_entry(|e| e.file_name() != ".nov") {
        let file = file?;
        if file.depth() == 0 {
            continue;
        }
        let path = file.path();
        let name = path.strip_prefix(&src_dir)?;
        // println!("Name: {name:?}\n\t{:?}", filter.check_decision(path)?);
        // if path.is_dir() && name.to_str().is_some_and(|f| f == ".nov") {
        //     println!("FOUND");
        // } else {
        // Schedule this path for unlinking.
        to_unlink.push(file.clone());
        match filter.check_decision(path)? {
            FilterDecision::Delete => {
   
                // We do not do anything and allow it to unlink.
            }
            FilterDecision::Encrypt => {
                // We just write it to the normal zip.
                enc_writer.write_path(path, name)?;
                // write_path_to_zip(&mut enc_zip, enc_options, path, name)?;
            }
            FilterDecision::IgnoreAndEncrypt => {
                // println!("IGNORE AND ENCRYPT: {:?}", path);
                sec_local_writer.write_path(path, name)?;
            }
            FilterDecision::Unsecure => {
                if path.is_dir() {
                    std::fs::create_dir_all(unsecure_path.join(name))?;
                } else {
                    std::fs::write(unsecure_path.join(name), std::fs::read(path)?)?;
                }
            } // }
        }
    }

    enc_writer.finish()?;
    sec_local_writer.finish()?;

    // Now it is time to unlink all of the directories.
    to_unlink.sort_by_cached_key(|f| std::cmp::Reverse(f.depth()));

    for path in to_unlink {
        if path.path().is_file() {
            std::fs::remove_file(path.path())?;
        } else {
            std::fs::remove_dir_all(path.path())?;
        }
    }

    std::fs::rename(&zip_loc, path.join("vault.bin"))?;

    std::fs::write(
        path.join(".gitignore"),
        "# NOVAULT\n# DO NOT MODIFY THIS\n/.nov/unsecure\n/.nov/secure_local",
    )?;
    std::fs::write(
        path.join(".gitattributes"),
        "# NOVAULT\n# DO NOT MODIFY THIS\nvault.bin binary",
    )?;

    Ok(())
}

fn get_repo_state(root: impl AsRef<Path>) -> Result<NovState> {
    if !exists_metadata_directory(root.as_ref()) {
        return Ok(NovState::Uninit);
    }
    Ok(StateFile::new(root.as_ref()).get_state()?)
}

pub fn seal_full(root: impl AsRef<Path>) -> Result<()> {
    let path = root.as_ref();
    let mut usr_input = get_password_with_prompt(false)?;

    seal_with_pwd(path, &mut usr_input)?;

    Ok(())
}

fn seal_with_pwd(root: impl AsRef<Path>, password: &mut CachedPassword) -> Result<()> {
    let path = root.as_ref();
    let state_file = StateFile::new(path);

    // Get the wrapped key.
    let wrapped = state_file.get_mk()?;

    let (new_wrap, master) = wrapped.get_master_key(password)?;

    match state_file.get_state()? {
        NovState::Unsealed => {}
        _ => {
            return Err(anyhow!(
                "We cannot seal a vault that it not in the unsealed state."
            ));
        }
    }

    // Perform the actual sealing.
    seal_postmigrate(path, &master)?;

    // Update the status.
    state_file.set_state(NovState::Sealed)?;

    // Now we need to move the .git back out to the top.
    std::fs::rename(
        path.join(".nov").join("wrap").join("external.git"),
        path.join(".git"),
    )?;

    // Remove the wrap directory as it serves no purpose when we are sealed.
    std::fs::remove_dir(path.join(".nov").join("wrap"))?;

    state_file.set_mk(&new_wrap)?;
    Ok(())
}

pub fn unseal(root: impl AsRef<Path>) -> Result<()> {
    let path = root.as_ref();

    // Check the status.
    match get_repo_state(path)? {
        NovState::Sealed => {}
        x => {
            return Err(anyhow!(
                "We cannot unseal a vault that it not in the sealed state. The vault is currently in the {x:?} state."
            ));
        }
    }

    let vault_path = path.join("vault.bin");

    if !vault_path.exists() {
        return Err(anyhow!("No vault binary file."));
    }

    if !exists_git_repo(path) {
        return Err(anyhow!(
            "Tried to re-seal, but there was no external git repo."
        ));
    }

    let mut password = prompt_password(false)?;

    // Now we perform an unseal with the password.
    unseal_with_pwd(path, &mut password)?;

    Ok(())
}

fn unseal_with_pwd(root: impl AsRef<Path>, password: &mut CachedPassword) -> Result<()> {
    let path = root.as_ref();
    let vault_path = path.join("vault.bin");

    let sec_local_path = path.join(".nov").join("secure_local").join("inpro.bin");

    let state_file = StateFile::new(path);

    let wrapped = state_file.get_mk()?;

    let master = wrapped.get_master_key_with_no_rewrap(password)?;


  

    console_log!(Info, "Decrypting the vault itself...");
    // Decrypt the vault itself.
    let vault = decrypt_zip(&vault_path, &master)?;

    console_log!(Info, "Decrypting the locally secured files...");
    // Get the locally secured files.
    let sec_local = decrypt_zip(&sec_local_path, &master)?;



    // If decryption passes we can start doing mutable ops.
    // Create the wrap directory.
    let wrap = path.join(".nov").join("wrap");
    if !wrap.exists() {
        std::fs::create_dir_all(&wrap)?;
    }

    // Move it into the wrap directory.
    std::fs::rename(path.join(".git"), wrap.join("external.git"))?;

    // Remove the ignore and attributes files.
    std::fs::remove_file(path.join(".gitignore"))?;
    std::fs::remove_file(path.join(".gitattributes"))?;

    // Expand the files into the main directory.
    expand_decrypted_bin(path, vault)?;

    // Expand the locally secured files.
    expand_decrypted_bin(path, sec_local)?;

    // Erase the vault binary.
    std::fs::remove_file(path.join("vault.bin"))?;

    // Remove the locally secured files.
    std::fs::remove_dir_all(path.join(".nov").join("secure_local"))?;

    // Relocate unsecure files.
    relocate_unsecure_files(path)?;


    state_file.set_state(NovState::Unsealed)?;


    Ok(())
}

fn relocate_unsecure_files(root: impl AsRef<Path>) -> Result<()> {
    let path = root.as_ref();


    let unsecure_path = path.join(".nov").join("unsecure");


    for dir in WalkDir::new(&unsecure_path) {
        let dir = dir?;
        if dir.depth() == 0 {
            continue;
        }
        let lpath = dir.path();
        let name = lpath.strip_prefix(&unsecure_path)?;

        if !lpath.exists() {
            // TODO: How do we want to handle this case?
        } else {
            std::fs::rename(lpath, path.join(name))?;
        }
    }

    // Now we delete the directory.
    std::fs::remove_dir_all(unsecure_path)?;

    Ok(())
}

fn decrypt_zip(vault_path: &Path, master: &MasterVaultKey) -> Result<Vec<u8>> {
     let mut header = std::fs::read(&vault_path)?;

    let mut vault = header.split_off(32);

    decrypt(&mut header, &mut vault, master.key_bytes())?;
    Ok(vault)
}

fn expand_decrypted_bin(path: &Path, vault: Vec<u8>) -> Result<()> {
    let mut real = ZipArchive::new(Cursor::new(vault))?;

    for i in 0..real.len() {
        let mut entry = real.by_index(i)?;

        let rel_path = match entry.enclosed_name() {
            Some(p) => p.to_owned(),
            None => continue,
        };

        let out_path = path.join(rel_path);

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut outfile = File::create(&out_path)?;
            std::io::copy(&mut entry, &mut outfile)?;
        }
    }
    Ok(())
}

/// Performs a sync, which basically detects which mode
/// we are currently in.
pub fn sync(root: impl AsRef<Path>) -> Result<()> {
    require_seal(
        root.as_ref(),
        |sf| match sf.get_remote()? {
            Some(_) => Ok(()),
            None => Err(anyhow!("The remote URL is not set. Please run link first.")),
        },
        || {
            console_log!(Info, "Performing synchronization...");
            git_add_commit_push(root.as_ref())?;
            Ok(())
        },
    )?;

    Ok(())
}

struct TermGuard;

impl TermGuard {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// This is a way
pub fn open(root: impl AsRef<Path>) -> Result<()> {
    if [NovState::Init, NovState::Uninit].contains(&get_repo_state(root.as_ref())?) {
        return Err(anyhow!(
            "The repository must be either sealed or unsealed to open it."
        ));
    }

    let wrapped = StateFile::new(root.as_ref()).get_mk()?;
    let mut password = fetch_password(&wrapped)?;

    // Opens the internals.
    let e = open_internal(root.as_ref(), &mut password);

    if let Ok(NovState::Unsealed) = get_repo_state(root.as_ref()) {
        seal_with_pwd(root.as_ref(), &mut password)?;
    }

    e
}

fn open_internal(root: impl AsRef<Path>, password: &mut CachedPassword) -> Result<()> {
    let path = root.as_ref();

    if get_repo_state(path)? == NovState::Sealed {
        unseal_with_pwd(path, password)?;
    }

    console_log!(Info, "The repository is open for editing.");
    console_log!(
        Info,
        "Commands:\n\t(Q) Quit and re-seal.\n\t(S) Synchronize"
    );

    let _guard = TermGuard::new();
    loop {
        match read()? {
            Event::Key(key) => {
                if key.is_press() {
                    if key.code == KeyCode::Char('q')
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL))
                    {
                        break;
                    }
                    if key.code == KeyCode::Char('s') {
                        console_log!(Info, "Synchronizing repository with remote...");

                        require_seal_with_retrieval(
                            root.as_ref(),
                            |sf| match sf.get_remote()? {
                                Some(_) => Ok(()),
                                None => Err(anyhow!("The remote URL is not set. Please run link first.")),
                            },
                            |_| {
                                Ok(password.clone())
                            },
                            || {
                                console_log!(Info, "Performing synchronization...");
                                git_add_commit_push(root.as_ref())?;
                                Ok(())
                            },
                        )?;

                        console_log!(Info, "Synchronization complete...");
                    }
                }
            }
            _ => {}
        }
    }
    // disable_raw_mode()?;
    drop(_guard);
    console_log!(Info, "Resealing the repository...");

    Ok(())
}

/// This is a guard that makes sure things happen in the correct order
/// and is used for a few operations that require the seal-unseal pattern.
fn require_seal<PF, F>(root: impl AsRef<Path>, pf_functor: PF, functor: F) -> Result<()>
where
    PF: FnMut(&StateFile) -> Result<()>,
    F: FnMut() -> Result<()>,
{
    require_seal_with_retrieval(root, pf_functor, fetch_password, functor)
}

/// This is a guard that makes sure things happen in the correct order
/// and is used for a few operations that require the seal-unseal pattern.
fn require_seal_with_retrieval<PF, KR, F>(
    root: impl AsRef<Path>,
    mut pf_functor: PF,
    mut kr_functor: KR,
    mut functor: F,
) -> Result<()>
where
    PF: FnMut(&StateFile) -> Result<()>,
    KR: FnMut(&WrappedKey) -> Result<CachedPassword>,
    F: FnMut() -> Result<()>,
{
    let path = root.as_ref();

    // First we need to see if we are actually initialized.
    if !exists_metadata_directory(path) {
        return Err(anyhow!(
            "Tried to synchronize a directory that is not initialized yet."
        ));
    }

    let state_file = StateFile::new(path);

    pf_functor(&state_file)?;

    let wrapped = state_file.get_mk()?;

    match get_repo_state(path)? {
        NovState::Uninit => {
            return Err(anyhow!("The target is not initialized."));
        }
        NovState::Init => {
            return Err(anyhow!(
                "It seems that the vault is in the init state, which usually means something went terribly wrong."
            ));
        }
        NovState::Sealed => {
            // Now we actually perform the synchronization
            // with the remote.
            functor()?;
            // Ok(())
        }
        NovState::Unsealed => {
            let mut fetch = kr_functor(&wrapped)?;

            // Now we perform a seal with the password, this
            // prevents us being re-prompted for the password.
            seal_with_pwd(path, &mut fetch)?;

            console_log!(Info, "Succesfully unsealed the vault.");

            let e = functor();

            // Now we restore the state by unsealing.
            unseal_with_pwd(path, &mut fetch)?;

            e?;

            // Ok(())
        }
    }

    Ok(())
}

fn parse_link(url: &str) -> Result<String> {
    // Form 1: git@github.com:JohnSmith/vault.git
    if url.starts_with("git@") {
        return Ok(url.to_string());
    } else {
        return Err(anyhow!(
            "We only support SSH style URLs at this time: git@github:JohnSmith/vault.git"
        ));
    }
}

pub fn link(root: impl AsRef<Path>, url: &str) -> Result<()> {
    let path = root.as_ref();

    // TODO: Check to see if the repository is well-formed.

    require_seal(
        root.as_ref(),
        |_| Ok(()),
        || {
            let url = parse_link(url)?;

            console_log!(Info, "Adding {url} as a remote origin...");
            add_remote_origin(path, &url)?;

            console_log!(Info, "Switching branch to main...");
            git_branch_main(path)?;

            console_log!(Info, "Pushing initial commit to main...");
            git_add_all(path)?;
            git_commit_all(path)?;
            git_push_origin(path)?;

            StateFile::new(path).set_remote(&url)?;

            console_log!(Info, "Succesfully linked to branch to remote!");

            Ok(())
        },
    )?;

    Ok(())
}

pub fn pull(root: impl AsRef<Path>, url: &str) -> Result<()> {
    let url = parse_link(url)?;

    if get_repo_state(root.as_ref())? != NovState::Uninit {
        return Err(anyhow!(
            "We cannot perform a pull unless the repository is uninitialized (i.e., an empty folder)."
        ));
    }

    git_clone(root.as_ref(), &url)?;

    Ok(())
}

fn get_password_with_prompt(confirm: bool) -> Result<CachedPassword> {
    print!("{} ", "PROMPT".magenta().bold());
    stdout().flush()?;

    let scan = CachedPassword::from_string(rpassword::prompt_password(if !confirm {
        "Enter vault password: "
    } else {
        "Confirm password: "
    })?);
    Ok(scan)
}

/// Prompts for a password, optionally asking for
/// password confirmation.
///
/// Getting the password with confirmation is commonly
/// used when we are initializing a new vault.
pub fn prompt_password(confirm: bool) -> Result<CachedPassword> {
    let first = get_password_with_prompt(false)?;

    if confirm {
        let second = get_password_with_prompt(true)?;

        if first == second {
            return Ok(first);
        } else {
            return Err(anyhow!("Passowrds fail to match."));
        }
    } else {
        Ok(first)
    }
}

pub fn fetch_password(wrapped: &WrappedKey) -> Result<CachedPassword> {
    match env::var("novpwd").map(CachedPassword::from_string) {
        Ok(mut e) => {
            console_log!(
                Info,
                "Found a password in the shell variables, trying the password."
            );
            if wrapped.get_master_key(&mut e).is_ok() {
                console_log!(Info, "Password succesfully verified.");
                Ok(e)
            } else {
                console_log!(
                    Error,
                    "The password could not be verified and thus will need to be entered manually."
                );
                prompt_password(false)
            }
        }
        Err(_) => prompt_password(false),
    }
}
