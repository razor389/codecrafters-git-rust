use crate::objects::{GitCommit, GitObject};
use crate::packfile::Packfile;
use reqwest::blocking::{Client, Response};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::{fs, str};
use crate::objects::Hash;

#[derive(Debug)]
pub struct HeadRef {
    pub symbolic_ref: String,  // e.g., "HEAD"
    pub points_to: String,     // e.g., "refs/heads/master"
}

#[derive(Debug)]
pub struct GitCapabilities {
    pub refs: HashMap<String, String>,  // Changed to HashMap<String, String>
    pub capabilities: Vec<String>,
    pub head: Option<HeadRef>,  // Store HEAD ref info here
}

/// Function to fetch refs using the smart HTTP protocol
pub fn fetch_refs(repo_url: &str) -> Result<GitCapabilities, Box<dyn Error>> {
    // Step 1: Send an HTTP request to the remote repository
    let refs_url = format!("{}/info/refs?service=git-upload-pack", repo_url);
    let client = Client::new();
    let response = client.get(&refs_url).send()?;

    // Step 2: Check the HTTP status code and content type
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !(status.is_success() || status == 304) {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to fetch refs, status: {}", status),
        )));
    }

    if content_type != "application/x-git-upload-pack-advertisement" {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Unexpected content-type: {}", content_type),
        )));
    }

    let body = response.text()?;
    println!("response body: {}", body);

    // Step 3: Validate that the first line starts with the correct pkt-line format
    let mut lines = body.lines();
    if let Some(first_line) = lines.next() {
        let service_prefix = "# service=git-upload-pack";
        if !first_line.contains(service_prefix) {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid service response",
            )));
        }
    }

    // Step 4: Parse refs and capabilities from pkt-lines
    let mut refs: HashMap<String, String> = HashMap::new();  // Use HashMap for refs
    let mut capabilities = Vec::new();
    let mut first_ref = true;
    let mut head_ref = None;

    for line in lines {
        if line == "0000" {
            break; // End of the pkt-line stream
        }

        if line.len() > 4 {
            let actual_line = &line[4..]; // Remove the 4-character length prefix
            if first_ref {
                // The first ref line contains capabilities
                if let Some((sha1, rest)) = actual_line.split_once(" ") {
                    if let Some((ref_name, cap_list)) = rest.split_once('\0') {
                        refs.insert(ref_name.to_string(), sha1.to_string());
                        // Capabilities end before symref and similar metadata
                        for cap in cap_list.split_whitespace() {
                            if cap.starts_with("symref=HEAD:") {
                                let symref_value = cap.strip_prefix("symref=HEAD:").unwrap();
                                head_ref = Some(HeadRef {
                                    symbolic_ref: "HEAD".to_string(),
                                    points_to: symref_value.to_string(),
                                });
                            } else if !cap.starts_with("object-format=")
                                && !cap.starts_with("agent=")
                                && cap != "filter"
                            {
                                capabilities.push(cap.to_string());
                            }
                        }
                    }
                }
                first_ref = false;
            } else {
                // Parse remaining refs (no capabilities)
                if let Some((sha1, ref_name)) = actual_line.split_once(" ") {
                    refs.insert(ref_name.to_string(), sha1.to_string());
                }
            }
        }
    }

    // Return the refs and capabilities in a structured format
    Ok(GitCapabilities {
        refs,
        capabilities,
        head: head_ref,
    })
}

/// Function to request and receive the packfile
pub fn request_packfile(repo_url: &str, commit_sha: &str) -> Result<Response, Box<dyn Error>> {
    let client = Client::new();
    let packfile_url = format!("{}/git-upload-pack", repo_url);

    // Step 1: Construct the "want" packet to request the packfile for the HEAD commit
    let want_packet = format!("0032want {}\n00000009done\n", commit_sha);

    // Step 2: Send the "want" request to the server
    let response = client.post(&packfile_url)
        .body(want_packet)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .send()?;

    // Step 3: Process the packfile response
    if response.status().is_success() {
        println!("Packfile received");
        return Ok(response);
    } else {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to get packfile: {}", response.status()),
        )));
    }

}

/* fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_url = "https://github.com/codecrafters-io/git-sample-3.git";
    let git_caps = fetch_refs(repo_url)?;

    // Display the refs, capabilities, and HEAD ref
    println!("Capabilities: {:?}", git_caps.capabilities);
    if let Some(head) = &git_caps.head {
        println!("{:?} points to: {:?}", head.symbolic_ref, head.points_to);

        // Step 1: Use the SHA1 of the HEAD ref to request the packfile
        if let Some(commit_sha) = git_caps.refs.get(&head.points_to) {
            println!("Requesting packfile for commit: {}", commit_sha);
            let response = request_packfile(repo_url, commit_sha)?;

            // Step 2: Process the packfile, handling NAK and verifying signature
            let target_dir = ".";
            process_packfile(response, target_dir)?;

            // Step 3: After unpacking, build the repo from the HEAD commit (use the commit SHA you got from refs)
            build_repo_from_head(commit_sha)?;
        } else {
            println!("Could not find SHA1 for HEAD ref: {}", head.points_to);
        }
    }

    Ok(())
}
 */

pub fn build_repo_from_head(commit_sha: &str, target_dir: &Path) -> io::Result<()> {
    // Step 1: Read the commit object using the commit_sha passed from main
    let commit = GitObject::read(commit_sha)?;

    if let GitObject::Commit(commit) = commit {
        // Step 2: Process the tree associated with this commit
        rebuild_from_tree(commit.tree, target_dir)?;
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid HEAD commit object"));
    }

    Ok(())
}

/// Function to process the packfile response and handle NAK, packfile header, and remaining data
pub fn process_packfile_and_find_head(mut response: Response, target_dir: &str) -> io::Result<Hash> {
    let mut packfile_data = Vec::new();
    response.read_to_end(&mut packfile_data)?;

    // Step 1: Handle the initial "0008NAK\n" (pkt-line NAK response)
    let nak_prefix = b"0008NAK\n";
    if packfile_data.starts_with(nak_prefix) {
        println!("Received NAK, continuing to process the packfile...");
        packfile_data.drain(0..nak_prefix.len());
    }

    // Step 2: Verify packfile signature ("PACK")
    if &packfile_data[0..4] != b"PACK" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packfile signature"));
    }
    println!("Valid packfile signature: PACK");

    // Step 3: Check the version (next 4 bytes should be version 2)
    let version = u32::from_be_bytes([packfile_data[4], packfile_data[5], packfile_data[6], packfile_data[7]]);
    if version != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unsupported packfile version: {}", version)));
    }
    println!("Packfile version: {}", version);

    // Step 4: Get the number of objects (next 4 bytes)
    let num_objects = u32::from_be_bytes([packfile_data[8], packfile_data[9], packfile_data[10], packfile_data[11]]);
    println!("Number of objects: {}", num_objects);

    // Step 5: Write the packfile to the .git/objects/pack directory
    let pack_dir = format!("{}/.git/objects/pack", target_dir);
    fs::create_dir_all(&pack_dir)?;

    let pack_file_path = format!("{}/packfile.pack", pack_dir);
    let mut pack_file = File::create(&pack_file_path)?;
    pack_file.write_all(&packfile_data[12..])?;

    // Step 6: Unpack the objects and track commit objects
    let mut packfile = File::open(&pack_file_path)?;
    let mut packfile_instance = Packfile::new(&mut packfile, num_objects);
    println!("unpack and collect commits");
    let commit_objects = packfile_instance.unpack_and_collect_commits()?;

    // Step 7: Find the head commit (commit with no parent or most recent based on timestamp)
    let head_commit = find_head_commit(commit_objects)?;
    println!("found head commit: {}", head_commit.to_hex());
    Ok(head_commit)
}

fn find_head_commit(commits: Vec<GitCommit>) -> io::Result<Hash> {
    if commits.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No commits found in packfile"));
    }

    // // Option 1: Find the commit with no parent
    // if let Some(commit) = commits.iter().find(|c| c.parent.is_none()) {
    //     return Ok(commit.hash());
    // }

    // Option 2: Find the most recent commit based on timestamp
    let latest_commit = commits.into_iter().max_by_key(|c| c.timestamp).unwrap();
    Ok(GitObject::Commit(latest_commit).hash())
}

// Rebuilds the file system structure from a Git tree object
fn rebuild_from_tree(tree_hash: Hash, target_dir: &Path) -> io::Result<()> {
    // Step 1: Read the tree object from the .git/objects directory
    let tree_object = GitObject::read_by_hash(tree_hash)?;

    // Step 2: Check if the tree object is actually a tree
    if let GitObject::Tree(entries) = tree_object {
        for entry in &entries {
            println!("{} {} {}", entry.mode, entry.object.to_hex(), entry.name);
        }
        println!("\n");

        // Iterate over the entries in the tree
        for entry in entries {
            // Build the full path by appending the entry name to the current target directory
            let path: PathBuf = target_dir.join(&entry.name);
            
            // Handle directories
            if entry.mode == "40000" {  // Git mode for directories
                // If a file exists where the directory should be, remove it
                if path.exists() && path.is_file() {
                    //println!("Removing file '{}' to create directory", path.display());
                    fs::remove_file(&path)?;
                }

                // Create the directory if it does not exist
                if !path.exists() {
                    //println!("Creating directory: {:?}", path.display());
                    fs::create_dir_all(&path)?;
                }

                // Recursively rebuild the subdirectory tree
                //println!("Entering directory: {:?}", path.display());
                rebuild_from_tree(entry.object, &path)?;

            } else {
                // Handle files
                // If a directory exists where the file should be, remove it
                if path.exists() && path.is_dir() {
                    //println!("Removing directory '{}' to create file", path.display());
                    fs::remove_dir_all(&path)?;
                }

                // Extract the blob and write the contents to the file
                let blob_object = GitObject::read_by_hash(entry.object)?;
                if let GitObject::Blob(contents) = blob_object {
                    //println!("Writing file: {:?}", path.display());
                    let mut file = File::create(&path)?;
                    file.write_all(&contents)?;
                }
            }
        }
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected tree object"));
    }

    Ok(())
}

