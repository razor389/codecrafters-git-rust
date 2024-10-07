use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use crate::objects::{GitCommit, GitObject, Hash};
use req_packfile::{build_repo_from_head, fetch_refs, process_packfile_and_find_head, request_packfile};

mod objects;
mod object_headers;
mod packfile;
mod req_packfile;

/// Define the CLI structure using Clap
#[derive(Parser)]
#[command(name = "git-rust")]
#[command(about = "A simple git-like version control system written in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Git repository
    Init,

    /// Hash a file and optionally write it as a blob object in the .git/objects directory
    HashObject {
        /// Path to the file to hash
        file: String,
        /// Write the object to the .git/objects directory
        #[arg(short = 'w', long = "write")]
        write: bool,
    },

    /// Display the content of an object by its SHA-1 hash
    CatFile {
        /// The hash of the object to display
        hash: String,
        /// Pretty-print the content of the object (without requiring the object type)
        #[arg(short = 'p')]
        pretty_print: bool,
    },

    /// Write the tree object based on the current working directory
    WriteTree,

    /// List the contents of a tree object by its SHA-1 hash
    LsTree {
        /// The hash of the tree object to list
        tree_hash: String,
        /// Show only the names of the files
        #[arg(long = "name-only")]
        name_only: bool,
    },

    /// Commit a tree object, optionally specifying parent commits and a message
    CommitTree {
        /// SHA-1 of the tree object to commit
        tree_sha: String,
        /// SHA-1 of a parent commit (can be repeated for multiple parents)
        #[arg(short = 'p', long = "parent")]
        parent_commits: Vec<String>,
        /// Commit message
        #[arg(short = 'm', long = "message")]
        message: String,
    },
    /// Show the details of a commit object by its SHA-1 hash
    Show {
        /// The SHA-1 hash of the commit object to show
        commit_hash: String,
    },
    /// Clone a remote repository
    Clone {
        /// URL of the remote repository
        repo_url: String,
        /// Directory to clone into
        target_dir: String,
    }
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => init_command(),
        Commands::HashObject { file, write } => hash_object_command(file, *write),
        Commands::CatFile { hash, pretty_print } => cat_file_command(hash, *pretty_print),
        Commands::WriteTree => write_tree_command(),
        Commands::LsTree { tree_hash, name_only } => ls_tree_command(tree_hash, *name_only),
        Commands::CommitTree {
            tree_sha,
            parent_commits,
            message,
        } => commit_tree_command(tree_sha, parent_commits, message),
        Commands::Show { commit_hash } => show_command(commit_hash),
        Commands::Clone { repo_url, target_dir } => clone_command(repo_url, target_dir),
    }
}

fn init_command() -> io::Result<()> {
    // Define the .git directory
    let git_dir = Path::new(".git");

    // Check if .git already exists
    if git_dir.exists() {
        println!("Reinitialized existing Git repository in {}/.git", std::env::current_dir()?.display());
    } else {
        // Create the .git directory and necessary subdirectories
        fs::create_dir(git_dir)?;
        fs::create_dir(git_dir.join("objects"))?;
        fs::create_dir_all(git_dir.join("refs"))?;

        // Create the HEAD file
        let mut head_file = fs::File::create(git_dir.join("HEAD"))?;
        head_file.write_all(b"ref: refs/heads/master\n")?;

        println!("Initialized empty Git repository in {}/.git", std::env::current_dir()?.display());
    }

    Ok(())
}

fn hash_object_command(file: &str, write: bool) -> io::Result<()> {
    let file_path = Path::new(file);

    // Read the file content
    let content = fs::read(file_path)?;

    // Create a blob object
    let blob = objects::GitObject::Blob(content);

    // Print the SHA-1 hash of the blob
    let hash = blob.hash();
    println!("{}", hash.to_hex());

    // If the -w flag is passed, write the blob object to the .git/objects directory
    if write {
        blob.write()?;
        println!("Object written to .git/objects");
    }

    Ok(())
}

fn cat_file_command(hash: &str, pretty_print: bool) -> io::Result<()> {
    // Read the object from the .git/objects directory
    let blob = objects::GitObject::read(hash)?;

    // If the -p flag is passed, pretty-print the content without requiring the object type
    if pretty_print {
        if let objects::GitObject::Blob(content) = blob {
            print!("{}", String::from_utf8_lossy(&content));
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Object is not a blob"));
        }
    } else {
        // In this case, you'd handle other object types if needed
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Only 'blob' type is supported for now"));
    }

    Ok(())
}

fn write_tree_command() -> io::Result<()> {
    let entries = objects::read_current_directory()?;
    let tree = objects::GitObject::Tree(entries);
    let hash = tree.hash();

    tree.write()?;
    println!("{}", hash.to_hex());

    Ok(())
}

/// Print the contents of a tree object
fn ls_tree_command(tree_hash: &str, name_only: bool) -> io::Result<()> {
    let tree = objects::GitObject::read(tree_hash)?;

    if let objects::GitObject::Tree(entries) = tree {
        for entry in entries {
            if name_only {
                println!("{}", entry.name);
            } else {
                println!("{} {} {}", entry.mode, entry.object.to_hex(), entry.name);
            }
        }
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Object is not a tree"));
    }

    Ok(())
}

/// Commit a tree object with an optional parent and commit message.
fn commit_tree_command(tree_sha: &str, parent_commits: &Vec<String>, message: &str) -> io::Result<()> {
    // Define author/committer information
    let author_name = "razor389".to_string();
    let author_email = "rgranowski@gmail.com".to_string();
    let committer_name = "razor389".to_string();
    let committer_email = "rgranowski@gmail.com".to_string();

    // Get the current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timezone = "+0000".to_string();  // Use UTC for simplicity

    // Convert the tree SHA to a Hash object
    let tree_hash = Hash::from_bytes(&hex::decode(tree_sha).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid tree SHA-1"))?)?;

    // Parse the parent commit hash if provided
    let parent_hash = if let Some(parent_sha) = parent_commits.get(0) {
        Some(Hash::from_bytes(&hex::decode(parent_sha).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid parent SHA-1"))?)?)
    } else {
        None
    };

    // Create the GitCommit object
    let commit = GitCommit {
        tree: tree_hash,
        parent: parent_hash,
        author_name,
        author_email,
        committer_name,
        committer_email,
        timestamp,
        timezone,
        message: message.to_string(),
    };

    // Wrap the commit object in GitObject::Commit
    let git_object = GitObject::Commit(commit);

    // Write the commit object to the .git/objects directory
    git_object.write()?;

    // Print the commit's SHA-1 hash
    println!("{}", git_object.hash().to_hex());

    Ok(())
}

/// Show the details of a commit object
// Function to convert a Unix timestamp to a human-readable string
fn format_timestamp(timestamp: u64) -> String {
    let d = UNIX_EPOCH + Duration::from_secs(timestamp);
    let datetime: chrono::DateTime<chrono::Utc> = d.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn show_command(commit_hash: &str) -> io::Result<()> {
    // Read the object from the .git/objects directory
    let git_object = GitObject::read(commit_hash)?;

    // Match on the object type and ensure it's a commit
    if let GitObject::Commit(commit) = git_object {
        // Print commit details
        println!("commit {}", commit_hash);
        println!("tree {}", commit.tree.to_hex());

        if let Some(parent) = commit.parent {
            println!("parent {}", parent.to_hex());
        }

        // Print author and committer details
        println!(
            "author {} <{}> {} {}",
            commit.author_name,
            commit.author_email,
            format_timestamp(commit.timestamp),
            commit.timezone
        );
        println!(
            "committer {} <{}> {} {}",
            commit.committer_name,
            commit.committer_email,
            format_timestamp(commit.timestamp),
            commit.timezone
        );

        // Print commit message
        println!("\n{}", commit.message);
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Object is not a commit"));
    }

    Ok(())
}

fn clone_command(repo_url: &str, clone_to_dir: &str) -> io::Result<()> {
    // Step 1: Create the target directory if it doesn't exist
    let target_path = Path::new(clone_to_dir);
    if !target_path.exists() {
        println!("Creating directory: {}", clone_to_dir);
        fs::create_dir_all(target_path)?;
    } else {
        println!("Directory already exists: {}", clone_to_dir);
    }

    // Step 2: Change the current directory to the target directory
    std::env::set_current_dir(target_path)?;

    // Step 3: Initialize the Git repository inside the target directory
    println!("Initializing Git metadata in target directory...");
    init_command()?;  // Ensure .git is created before cloning operations

    // Step 4: Fetch refs from the remote repository
    let git_caps = fetch_refs(repo_url).map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Failed to fetch refs: {}", err)))?;

    // Step 5: Use the SHA1 of the HEAD ref to request the packfile
    if let Some(commit_sha) = git_caps.refs.get(&git_caps.head.unwrap().points_to) {
        println!("Requesting packfile for commit: {}", commit_sha);
        let response = request_packfile(repo_url, commit_sha).map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Failed to request packfile: {}", err)))?;

        // Step 6: Process the packfile and find the correct head commit
        let head_commit = process_packfile_and_find_head(response, clone_to_dir)?;

        // Step 7: After unpacking, build the repo from the head commit
        println!("Building repository from head commit: {}", head_commit.to_hex());
        build_repo_from_head(&head_commit.to_hex(), target_path)?;

        // Step 8: Write the HEAD reference and point it to master
        write_ref_to_head(&head_commit.to_hex())?;
        println!("Finished building repo and initializing metadata.");

        // Step 9: Print the directory structure
        //println!("\nDirectory structure of '{}':", clone_to_dir);
        //print_directory_structure(target_path, 0)?;

    } else {
        println!("Could not find SHA1 for HEAD ref");
    }

    Ok(())
}

/// Writes the head commit SHA to refs/heads/master and updates the HEAD reference
fn write_ref_to_head(commit_hash: &str) -> io::Result<()> {
    let refs_heads_dir = Path::new(".git/refs/heads");

    // Ensure the refs/heads directory exists
    fs::create_dir_all(refs_heads_dir)?;

    // Write the commit hash to refs/heads/master
    let mut ref_file = fs::File::create(refs_heads_dir.join("master"))?;
    ref_file.write_all(commit_hash.as_bytes())?;
    
    println!("Written head ref (commit) to refs/heads/master: {}", commit_hash);
    
    Ok(())
}

/// Recursively prints the directory structure up to the specified depth.
fn print_directory_structure(path: &Path, depth: usize) -> io::Result<()> {
    if depth > 1 {
        return Ok(());
    }

    if path.is_dir() {
        // Read the directory contents
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let prefix = "  ".repeat(depth);  // Create an indented prefix based on the depth
            
            // Print the directory or file name
            if entry_path.is_dir() {
                println!("{}[DIR] {}", prefix, entry.file_name().to_string_lossy());
                // Recursively print the subdirectory contents
                print_directory_structure(&entry_path, depth + 1)?;
            } else {
                println!("{}[FILE] {}", prefix, entry.file_name().to_string_lossy());
            }
        }
    }

    Ok(())
}