use clap::Parser;

/// A simple program to manage a remote repository that
/// is encrypted before being pushed to the cloud.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) enum Args {
    /// Initializes a new repository. 
    Init {
        
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String
    },
    /// Seals a repository, encrypting it.
    Seal {
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String
    },
    /// Unseals a repository, decrypting it.
    Unseal {
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String
    },
    /// Syncs local changes with the cloud.
    Sync {
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String
    },
    /// Links the repository with a remote branch.
    Link {
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String,
        url: String
    },
    /// Pulls a remote vault down to local.
    Pull {
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String,
        /// The git url (SSH-form) to pull from.
        url: String
    },
    /// Opens the vault for editing, when the process closes it
    /// will automatically seal again. This is highly recommended instead
    /// of manually sealing and unsealing.
    Open {
        #[arg(short, long, default_value=".")]
        /// The target directory.
        target: String,
    }
}


