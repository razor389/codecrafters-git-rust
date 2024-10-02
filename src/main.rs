use std::env;
use std::fs;
use bytes::Bytes;
use std::io::{self, Read, Write};
use std::path::Path;
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use packfile::store_packfile;
use reqwest::Body;
use sha1::{Sha1, Digest};
use git2::{Repository, Oid};
//use reqwest::Url;
use tokio;
mod packfile;


#[tokio::main]
async fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Please provide a command.");
        return;
    }

    match args[1].as_str() {
        "init" => {
            // Initialize the .git directory
            fs::create_dir(".git").unwrap();
            fs::create_dir(".git/objects").unwrap();
            fs::create_dir(".git/refs").unwrap();
            fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
            println!("Initialized git directory");
        }
        "cat-file" => {
            // Ensure correct usage
            if args.len() != 4 || args[2] != "-p" {
                eprintln!("Usage: cat-file -p <blob_sha>");
                return;
            }
            // Handle `git cat-file -p <blob_sha>`
            let blob_sha = &args[3];
            match print_blob_content(blob_sha) {
                Ok(_) => (),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "hash-object" => {
            // Ensure correct usage
            if args.len() != 4 || args[2] != "-w" {
                eprintln!("Usage: hash-object -w <file>");
                return;
            }

            // Handle `git hash-object -w <file>`
            let file_path = &args[3];
            match create_blob(file_path) {
                Ok(sha1_hash) => println!("{}", sha1_hash),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "ls-tree" => {
            if args.len() < 2 {
                eprintln!("Usage: ls-tree [--name-only] <tree_sha>");
                return;
            }

            let mut name_only = false;
            let tree_sha;

            // Check if the --name-only flag is provided
            if args.len() == 4 && args[2] == "--name-only" {
                name_only = true;
                tree_sha = &args[3];  // tree_sha is in args[3] if --name-only is present
            } else if args.len() == 3 {
                tree_sha = &args[2];  // tree_sha is in args[2] if --name-only is absent
            } else {
                eprintln!("Usage: ls-tree [--name-only] <tree_sha>");
                return;
            }

            // Call the function to list the tree entries
            match list_tree(tree_sha, name_only) {
                Ok(_) => (),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "write-tree" => {
            // Call the function to write the tree and output the SHA1 of the tree
            match write_tree() {
                Ok(tree_sha) => println!("{}", tree_sha),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "commit-tree" => {
            // Parse arguments for commit-tree
            let mut tree_sha = None;
            let mut commit_message = None;
            let mut parent_sha = None;

            let mut i = 2;  // Start parsing after the command
            while i < args.len() {
                match args[i].as_str() {
                    "-m" => {
                        if i + 1 >= args.len() {
                            eprintln!("Error: No commit message provided with -m.");
                            return;
                        }
                        commit_message = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "-p" => {
                        if i + 1 >= args.len() {
                            eprintln!("Error: No parent commit SHA provided with -p.");
                            return;
                        }
                        parent_sha = Some(args[i + 1].clone());
                        i += 2;
                    }
                    _ => {
                        // Any unrecognized argument will be treated as the tree SHA
                        if tree_sha.is_none() {
                            tree_sha = Some(args[i].clone());
                        } else {
                            eprintln!("Error: Unknown argument '{}'.", args[i]);
                            return;
                        }
                        i += 1;
                    }
                }
            }

            // Ensure we have the mandatory arguments (tree_sha and message)
            let tree_sha = match tree_sha {
                Some(sha) => sha,
                None => {
                    eprintln!("Error: No tree SHA provided.");
                    return;
                }
            };
            let commit_message = match commit_message {
                Some(msg) => msg,
                None => {
                    eprintln!("Error: No commit message provided.");
                    return;
                }
            };

            // Call the function to create the commit
            match create_commit(&tree_sha, &commit_message, parent_sha.as_deref()) {
                Ok(commit_sha) => println!("{}", commit_sha),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        
        "clone" => {
            if args.len() != 4 {
                eprintln!("Usage: clone <remote_repo> <directory>");
                return;
            }

            let remote_repo = &args[2];
            let target_dir = &args[3];

           match clone_repo(remote_repo, target_dir).await{
                Ok(()) => println!("cloned repo"),
                Err(e) => eprintln!("error cloning repo: {}", e),
           }
        }

        _ => {
            println!("unknown command: {}", args[1]);
        }
    }
}

// Function to decode and print the blob content from the .git/objects directory
fn print_blob_content(blob_sha: &str) -> io::Result<()> {
    if blob_sha.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid blob SHA"));
    }

    let dir = &blob_sha[0..2];
    let file = &blob_sha[2..];

    let object_path = format!(".git/objects/{}/{}", dir, file);

    if !Path::new(&object_path).exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Object not found"));
    }

    let compressed_data = fs::read(&object_path)?;
    let mut decoder = flate2::read::ZlibDecoder::new(&compressed_data[..]);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    if let Some(null_pos) = decompressed_data.iter().position(|&b| b == 0) {
        let content = &decompressed_data[null_pos + 1..];
        print!("{}", String::from_utf8_lossy(content));
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid object format"));
    }

    Ok(())
}

// Function to create a blob from the file, store it, and return the SHA-1 hash
fn create_blob(file_path: &str) -> io::Result<String> {
    // Read the file content
    let content = fs::read(file_path)?;

    // Create the blob header
    let blob_header = format!("blob {}\0", content.len());
    let mut blob_data = Vec::new();
    blob_data.extend(blob_header.as_bytes());
    blob_data.extend(&content);

    // Compute SHA-1 hash of the blob
    let mut hasher = Sha1::new();
    hasher.update(&blob_data);
    let sha1_hash = hasher.finalize();
    let sha1_hex = hex::encode(sha1_hash);

    // Prepare the directory and file paths
    let dir = &sha1_hex[0..2];
    let file = &sha1_hex[2..];
    let object_dir = format!(".git/objects/{}", dir);
    let object_path = format!("{}/{}", object_dir, file);

    // Create the object directory if it doesn't exist
    if !Path::new(&object_dir).exists() {
        fs::create_dir(&object_dir)?;
    }

    // Compress the blob data using zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&blob_data)?;
    let compressed_data = encoder.finish()?;

    // Write the compressed blob to the object file
    let mut object_file = File::create(object_path)?;
    object_file.write_all(&compressed_data)?;

    Ok(sha1_hex)
}

// Function to list the tree entries, either full or name-only
fn list_tree(tree_sha: &str, name_only: bool) -> io::Result<()> {
    if tree_sha.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid tree SHA"));
    }

    let dir = &tree_sha[0..2];
    let file = &tree_sha[2..];

    let object_path = format!(".git/objects/{}/{}", dir, file);

    if !Path::new(&object_path).exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Tree object not found"));
    }

    // Read and decompress the tree object data
    let compressed_data = fs::read(&object_path)?;
    let mut decoder = ZlibDecoder::new(&compressed_data[..]);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    // The first part is the object header, which we need to skip.
    // The header format is: "tree <size>\0", where <size> is the size of the actual object data.
    if let Some(null_byte_pos) = decompressed_data.iter().position(|&b| b == 0) {
        // Skip the header
        let object_data = &decompressed_data[null_byte_pos + 1..];

        // Now process the tree entries in the object_data
        parse_tree_entries(object_data, name_only)?;
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid tree object format"));
    }

    Ok(())
}

// Function to parse tree entries and output either full or name-only
fn parse_tree_entries(object_data: &[u8], name_only: bool) -> io::Result<()> {
    let mut i = 0;

    while i < object_data.len() {
        // Parse the mode (until the first space)
        let space_pos = object_data[i..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid tree format: no space found"))?;

        // Extract the mode (e.g., "100644" for files or "40000" for directories)
        let mode = String::from_utf8_lossy(&object_data[i..i + space_pos]);
        i += space_pos + 1;  // Skip the mode and the space

        // Find the first null byte separating the name from the SHA-1 hash
        let null_pos = object_data[i..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid tree format: no null byte found"))?;

        // Extract the file/directory name
        let name = String::from_utf8_lossy(&object_data[i..i + null_pos]);
        i += null_pos + 1;  // Skip the null byte

        // Extract the SHA-1 hash (next 20 bytes)
        let sha1 = &object_data[i..i + 20];
        let sha1_str = hex::encode(sha1);
        i += 20;  // Skip the 20-byte SHA-1 hash

        // Determine if it's a blob (file) or a tree (directory)
        let object_type = if mode == "40000" { "tree" } else { "blob" };

        // Output based on whether --name-only was passed
        if name_only {
            println!("{}", name);
        } else {
            // Full output: "<mode> <type> <sha> <name>"
            println!("{} {} {}    {}", mode, object_type, sha1_str, name);
        }
    }

    Ok(())
}

fn write_tree() -> io::Result<String> {
    // Get the current directory
    let current_dir = Path::new(".");

    // Recursively write tree for the current directory and return the SHA-1 of the tree object
    write_tree_recursive(current_dir)
}


fn write_tree_recursive(dir: &Path) -> io::Result<String> {
    let mut tree_entries = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy().to_string();

        if file_name_str == ".git" {
            continue; // Skip the .git directory
        }

        if path.is_file() {
            // It's a file, create a blob and get the SHA-1
            let sha1 = create_blob(&path.to_string_lossy())?;
            let mode = "100644"; // Regular file mode

            // Add the mode, name, and binary SHA-1 to the tree entry vector
            tree_entries.push((file_name_str.clone(), format!("{} {}\0", mode, file_name_str).into_bytes(), hex::decode(sha1).unwrap()));
        } else if path.is_dir() {
            // It's a directory, recursively write tree and get the tree SHA-1
            let sha1 = write_tree_recursive(&path)?;
            let mode = "40000"; // Directory mode

            // Add the mode, name, and binary SHA-1 to the tree entry vector
            tree_entries.push((file_name_str.clone(), format!("{} {}\0", mode, file_name_str).into_bytes(), hex::decode(sha1).unwrap()));
        }
    }

    // Sort the entries by their name (the first element of the tuple)
    tree_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Now concatenate the sorted entries into a single byte buffer
    let mut tree_data = Vec::new();
    for (_, entry_name_bytes, sha1_bytes) in tree_entries {
        tree_data.extend(entry_name_bytes); // Append mode + name + null byte
        tree_data.extend(sha1_bytes);       // Append the 20-byte binary SHA-1
    }

    // Create the tree header
    let tree_header = format!("tree {}\0", tree_data.len());
    let mut full_data = Vec::new();
    full_data.extend(tree_header.as_bytes());
    full_data.extend(tree_data);

    // Compute the SHA-1 of the tree object
    let mut hasher = Sha1::new();
    hasher.update(&full_data);
    let sha1_hash = hasher.finalize();
    let sha1_hex = hex::encode(sha1_hash);

    // Write the compressed tree object to the .git/objects directory
    let dir = &sha1_hex[0..2];
    let file = &sha1_hex[2..];
    let object_dir = format!(".git/objects/{}", dir);
    let object_path = format!("{}/{}", object_dir, file);

    if !Path::new(&object_dir).exists() {
        fs::create_dir(&object_dir)?;
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&full_data)?;
    let compressed_data = encoder.finish()?;

    let mut object_file = File::create(object_path)?;
    object_file.write_all(&compressed_data)?;

    Ok(sha1_hex)
}

// Function to create a commit object, store it, and return the commit SHA-1
fn create_commit(tree_sha: &str, message: &str, parent_sha: Option<&str>) -> io::Result<String> {
    // Author/committer information (In real-world, you would probably read this from a config)
    let author_name = "Author Name";
    let author_email = "author@example.com";
    let committer_name = "Committer Name";
    let committer_email = "committer@example.com";

    // Get the current time for the commit timestamp
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let timezone = "+0000"; // For simplicity, using UTC

    // Start building the commit data
    let mut commit_data = format!("tree {}\n", tree_sha);

    // If there is a parent commit, add it to the commit data
    if let Some(parent) = parent_sha {
        commit_data.push_str(&format!("parent {}\n", parent));
    }

    // Add author and committer information
    commit_data.push_str(&format!(
        "author {} <{}> {} {}\n",
        author_name, author_email, timestamp, timezone
    ));
    commit_data.push_str(&format!(
        "committer {} <{}> {} {}\n",
        committer_name, committer_email, timestamp, timezone
    ));

    // Add an extra newline before the commit message, as required by Git
    commit_data.push_str("\n");
    commit_data.push_str(message);
    commit_data.push_str("\n");

    // Create the commit header
    let commit_header = format!("commit {}\0", commit_data.len());
    let mut full_commit_data = Vec::new();
    full_commit_data.extend(commit_header.as_bytes());
    full_commit_data.extend(commit_data.as_bytes());

    // Compute the SHA-1 of the commit object
    let mut hasher = Sha1::new();
    hasher.update(&full_commit_data);
    let sha1_hash = hasher.finalize();
    let commit_sha = hex::encode(sha1_hash);

    // Write the compressed commit object to the .git/objects directory
    let dir = &commit_sha[0..2];
    let file = &commit_sha[2..];
    let object_dir = format!(".git/objects/{}", dir);
    let object_path = format!("{}/{}", object_dir, file);

    if !Path::new(&object_dir).exists() {
        fs::create_dir(&object_dir)?;
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&full_commit_data)?;
    let compressed_data = encoder.finish()?;

    let mut object_file = File::create(object_path)?;
    object_file.write_all(&compressed_data)?;

    // Update the HEAD to point to the new commit
    fs::write(".git/HEAD", format!("{}\n", commit_sha))?;

    Ok(commit_sha)
}

// Clone the repository from a remote HTTP repository
async fn clone_repo(remote_repo: &str, target_dir: &str) -> io::Result<()> {
    // Check if the target directory already exists
    if Path::new(target_dir).exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Target directory already exists"));
    }

    // Step 1: Initialize the .git directory
    fs::create_dir_all(format!("{}/.git/objects", target_dir))?;
    fs::create_dir_all(format!("{}/.git/refs", target_dir))?;
    fs::write(format!("{}/.git/HEAD", target_dir), "ref: refs/heads/master\n")?;

    // Step 2: Fetch the repository's refs (info/refs)
    let repo_url = format!("{}/info/refs?service=git-upload-pack", remote_repo);
    let refs_data = match fetch_refs(&repo_url).await {
        Ok(data) => data,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to fetch refs: {}", err))),
    };

    // Step 3: Parse refs and get the HEAD commit SHA
    let (head_commit_sha, capabilities) = match parse_refs(&refs_data) {
        Some((sha, caps)) => (sha, caps),
        None => return Err(io::Error::new(io::ErrorKind::NotFound, "HEAD commit not found")),
    };

    // Step 4: Request the packfile via POST to git-upload-pack
    let pack_data = fetch_packfile(remote_repo, &head_commit_sha, &capabilities).await?;

    // Step 5: Store the packfile in the .git directory
    store_packfile(target_dir, pack_data);

    // Step 6: Verify repository and objects
    verify_repository_and_objects(target_dir, &head_commit_sha)?;

    // Step 7: Write the working directory files (checkout the HEAD commit)
    checkout_head_commit(target_dir, &head_commit_sha)?;

    println!("Repository cloned successfully to {}", target_dir);

    Ok(())
}

async fn fetch_packfile(remote_repo: &str, head_commit_sha: &str, capabilities: &str) -> Result<Vec<u8>, io::Error> {
    let upload_pack_url = format!("{}/git-upload-pack", remote_repo);
    println!("Requesting packfile from: {}", upload_pack_url);

    // Step 1: Create the 'want' line and directly add the capabilities from the parse_refs result
    let want_line = format!("want {} {}\n", head_commit_sha, capabilities);

    // Step 2: Calculate the length of the want line including the 4-byte length prefix
    let want_length = format!("{:04x}", want_line.len() + 4);

    // Step 3: Construct the request body (pkt-line format)
    let mut request_body = format!("{}{}0000", want_length, want_line);

    println!("Constructed request body:\n{}", request_body); // Debugging

    // Step 4: Send a 'done' line to indicate the end of negotiation
    request_body.push_str("0009done\n");

    // Step 5: Send the POST request to fetch the packfile
    let client = reqwest::Client::new();
    let response = client
        .post(&upload_pack_url)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .body(Body::from(request_body))
        .send()
        .await
        .map_err(|err| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to request packfile: {}", err))
        })?;

    // Step 6: Check if the response is successful
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to fetch packfile: HTTP status {}", response.status()),
        ));
    }

    // Step 7: Handle the negotiation phase: discard intermediate responses like `NAK`
    let body_bytes = response.bytes().await.map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to read response bytes: {}", err))
    })?;

    println!("Received response: first 100 bytes: {:?}", &body_bytes[..100.min(body_bytes.len())]);

    // Parse and process the response, skipping control responses like NAK or ACK
    let packfile_data = process_negotiation_phase(body_bytes)?;

    // Step 8: Return the packfile data
    Ok(packfile_data)
}


// Process the server response and extract the actual packfile data
fn process_negotiation_phase(body_bytes: Bytes) -> io::Result<Vec<u8>> {
    let mut packfile_data = Vec::new();
    let mut pos = 0;

    // Read through the response and ignore non-packfile data like `NAK` and progress updates
    while pos < body_bytes.len() {
        // Extract the length prefix (first 4 bytes of a pkt-line)
        let length_prefix = &body_bytes[pos..pos + 4];
        let length = match std::str::from_utf8(length_prefix) {
            Ok(l) => usize::from_str_radix(l, 16).unwrap_or(0),
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to parse length prefix")),
        };

        pos += 4;

        // If the length is zero, it's a flush packet (pkt-line protocol)
        if length == 0 {
            continue;
        }

        // Extract the packet data
        let packet = &body_bytes[pos..pos + length - 4];
        let packet_str = std::str::from_utf8(packet).unwrap_or("");

        // Check for 'NAK' or 'ACK' packets and ignore them
        if packet_str.starts_with("NAK") || packet_str.starts_with("ACK") || packet_str.contains("continue") {
            println!("Received control packet: {}", packet_str);
        } else {
            // Check if we find the "PACK" header in the packet
            if let Some(pack_header_offset) = packet.windows(4).position(|window| window == b"PACK") {
                // Skip to the "PACK" header and store only the actual packfile data
                let pack_data_start = pos + pack_header_offset;
                println!("Found 'PACK' header at position {}", pack_data_start);

                // Append the packfile data starting from the "PACK" header
                packfile_data.extend_from_slice(&body_bytes[pack_data_start..]);
                break;  // No need to read more once we find the packfile
            }
        }

        pos += length - 4;
    }

    // Return the packfile data (this is what we'll store and validate later)
    if packfile_data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "No packfile data found"));
    }

    println!("Extracted packfile data, size: {} bytes", packfile_data.len());
    Ok(packfile_data)
}

// Check out the HEAD commit and write files to the working directory
fn checkout_head_commit(target_dir: &str, head_commit_sha: &str) -> io::Result<()> {
    let repo = Repository::open(target_dir).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to open repository: {}", err))
    })?;

    // Convert the SHA-1 string to an Oid
    let oid = Oid::from_str(head_commit_sha).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid commit SHA: {}", err))
    })?;

    // Find the commit object by OID
    let commit = repo.find_commit(oid).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to find commit: {}", err))
    })?;

    // Get the tree (directory structure) associated with the commit
    let tree = commit.tree().map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to find tree: {}", err))
    })?;

    // Perform the checkout to update the working directory
    repo.checkout_tree(tree.as_object(), None).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to checkout tree: {}", err))
    })?;

    // Update HEAD to point to the checked-out commit
    repo.set_head_detached(oid).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to set HEAD: {}", err))
    })?;

    println!("Checked out HEAD commit: {}", head_commit_sha);
    Ok(())
}

fn verify_repository_and_objects(target_dir: &str, head_commit_sha: &str) -> io::Result<()> {
    let repo = Repository::open(target_dir).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to open repository: {}", err))
    })?;

    // Check if the head commit exists in the repository
    let oid = git2::Oid::from_str(head_commit_sha).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid commit SHA: {}", err))
    })?;

    let _commit = repo.find_commit(oid).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to find commit: {}", err))
    })?;

    println!("Verified repository and found HEAD commit: {}", head_commit_sha);
    Ok(())
}


// Fetch the refs from the remote repository
async fn fetch_refs(repo_url: &str) -> Result<Vec<u8>, io::Error> {
    println!("Fetching refs from: {}", repo_url); // Debug: print the URL being fetched

    let response = reqwest::get(repo_url).await.map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to send request: {}", err))
    })?;

    let status = response.status(); // Get the status before consuming the response
    println!("HTTP Response: {}", status); // Debug: print the HTTP status

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "Unable to fetch response body".to_string());
        eprintln!("Error fetching refs: {} - {}", status, body);
        return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to fetch refs: HTTP status {}", status)));
    }

    let bytes = response.bytes().await.map_err(|err| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to read response bytes: {}", err))
    })?;

    println!("Received refs data (first 100 bytes): {:?}", &bytes[..100.min(bytes.len())]);

    Ok(bytes.to_vec())
}

fn parse_refs(refs_data: &[u8]) -> Option<(String, String)> {
    let refs_str = String::from_utf8_lossy(refs_data);

    // Debug: Print the entire refs response for analysis
    println!("Raw refs data: {}", refs_str);

    let mut sha_from_second_line: Option<String> = None;
    let mut capabilities: Option<String> = None;

    let mut lines_iter = refs_str.lines();

    while let Some(line) = lines_iter.next() {
        // Ignore the service announcement and pkt-line flush marker
        if line.starts_with("# service=git-upload-pack") || line == "0000" {
            continue;
        }

        // Second line has an 8-character length prefix
        if line.len() > 8 && line.starts_with("0000") {
            let line_content = &line[8..]; // Skip the first 8 characters (length prefix)

            if line_content.len() >= 40 {
                let (sha, rest) = line_content.split_at(40); // Extract the SHA (first 40 chars)
                let sha = sha.trim();
                let rest = rest.trim();

                sha_from_second_line = Some(sha.to_string()); // Store the SHA from second line

                // Split remaining line into ref name and capabilities
                let mut ref_parts = rest.split_whitespace();
                if let Some(_ref_name) = ref_parts.next() {
                    // Collect capabilities (everything between ref name and symref)
                    let caps: Vec<&str> = ref_parts
                        .take_while(|part| !part.starts_with("symref="))
                        .collect();
                    capabilities = Some(caps.join(" "));
                }
            }
        }
        // Third line has a 4-character length prefix
        else if line.len() > 4 {
            let line_content = &line[4..]; // Skip the first 4 characters (length prefix)

            if line_content.len() >= 40 {
                let (sha, _rest) = line_content.split_at(40); // Extract the SHA
                let sha = sha.trim();

                // Ensure SHA from third line matches the SHA from the second line
                if let Some(ref stored_sha) = sha_from_second_line {
                    if stored_sha == sha {
                        println!("SHA matches: {}", sha);
                        println!("capability: {:?}", capabilities);
                        // Return the SHA and capabilities
                        return Some((sha.to_string(), capabilities.unwrap_or_default()));
                    } else {
                        println!("SHA mismatch: second line SHA = {}, third line SHA = {}", stored_sha, sha);
                        return None;
                    }
                }
            }
        }
    }

    println!("HEAD ref not found.");
    None
}
