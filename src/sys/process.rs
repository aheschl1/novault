use std::{path::Path, process::Command};
use anyhow::{Result, anyhow};



pub fn add_remote_origin(root: &Path, url: &str) -> Result<()> {
    let status = Command::new("git")
        .args(vec![
            "remote".to_string(),
            "add".to_string(),
            "origin".to_string(),
            url.to_string()
        ])
        .current_dir(root)
        .output()?;
    if !status.status.success() {
        let std_err_utf8 = std::str::from_utf8(&status.stderr)?;
        return Err(anyhow!("Failed to properly add a remote origin:\n{}", std_err_utf8.trim()))
    }
    Ok(())
}

pub fn git_branch_main(root: &Path) -> Result<()> {
    let status = Command::new("git")
        .args(vec![
            "branch".to_string(),
            "-M".to_string(),
            "main".to_string()
        ])
        .current_dir(root)
        .output()?;
    if !status.status.success() {
        let std_err_utf8 = std::str::from_utf8(&status.stderr)?;
        return Err(anyhow!("Failed to properly switch to main:\n{}", std_err_utf8.trim()))
    }
    Ok(())
}

pub fn git_add_all(root: &Path) -> Result<()> {
    let status = Command::new("git")
        .args(vec![
            "add".to_string(),
            ".".to_string(),
        ])
        .current_dir(root)
        .output()?;
    if !status.status.success() {
        let std_err_utf8 = std::str::from_utf8(&status.stderr)?;
        return Err(anyhow!("Failed to properly git add .:\n{}", std_err_utf8.trim()))
    }
    Ok(())
}

pub fn git_commit_all(root: &Path) -> Result<()> {
    let status = Command::new("git")
        .args(vec![
            "commit".to_string(),
            "-m".to_string(),
            "vault update".to_string()
        ])
        .current_dir(root)
        .output()?;
    if !status.status.success() {
        let std_err_utf8 = std::str::from_utf8(&status.stderr)?;
        return Err(anyhow!("Failed to properly commit:\n{}", std_err_utf8.trim()))
    }
    Ok(())
}

pub fn git_push_origin(root: &Path) -> Result<()> {
    let status = Command::new("git")
        .args(vec![
            "push".to_string(),
            "-u".to_string(),
            "origin".to_string(),
            "main".to_string()
        ])
        .current_dir(root)
        .output()?;
    if !status.status.success() {
        let std_err_utf8 = std::str::from_utf8(&status.stderr)?;
        return Err(anyhow!("Failed to properly commit:\n{}", std_err_utf8.trim()))
    }
    Ok(())
}

pub fn git_add_commit_push(root: &Path) -> Result<()> {
    git_add_all(root)?;
    git_commit_all(root)?;
    git_push_origin(root)?;
    Ok(())
}

pub fn git_clone(root: &Path, url: &str) -> Result<()> {
    let status = Command::new("git")
        .args(vec![
            "clone".to_string(),
            url.to_string(),
            ".".to_string()
        ])
        .current_dir(root)
        .output()?;
    if !status.status.success() {
        let std_err_utf8 = std::str::from_utf8(&status.stderr)?;
        return Err(anyhow!("Failed to properly pull the remote origin:\n{}", std_err_utf8.trim()))
    }
    Ok(())
}