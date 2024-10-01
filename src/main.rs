use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use futures_util::StreamExt;
use reqwest::Body;
use sha1::{Sha1, Digest};
use git2::{Repository, Oid};
//use reqwest::Url;
use tokio;

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
            match clone_repo(remote_repo, target_dir).await {
                Ok(_) => println!("Cloned repository into {}", target_dir),
                Err(e) => eprintln!("Error: {}", e),
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
    let head_commit_sha = match parse_refs(&refs_data) {
        Some(sha) => sha,
        None => return Err(io::Error::new(io::ErrorKind::NotFound, "HEAD commit not found")),
    };

    // Step 4: Request the packfile via POST to git-upload-pack
    let pack_data = fetch_packfile(remote_repo, &head_commit_sha).await?;

    // Step 5: Store the packfile in the .git directory
    store_packfile(target_dir, pack_data)?;

    // Step 6: Verify repository and objects
    verify_repository_and_objects(target_dir, &head_commit_sha)?;

    // Step 7: Write the working directory files (checkout the HEAD commit)
    checkout_head_commit(target_dir, &head_commit_sha)?;

    println!("Repository cloned successfully to {}", target_dir);
    Ok(())
}

// Send a POST request to fetch the packfile for the HEAD commit
async fn fetch_packfile(remote_repo: &str, head_commit_sha: &str) -> Result<Vec<u8>, io::Error> {
    let upload_pack_url = format!("{}/git-upload-pack", remote_repo);
    println!("Requesting packfile from: {}", upload_pack_url);

    // Capabilities required by the server
    let capabilities = "multi_ack_detailed side-band ofs-delta shallow no-progress include-tag";

    // Calculate the length of the "want" command in pkt-line format
    // `0032` is the length of the packet (52 in hexadecimal), including the capabilities
    let want_line = format!("want {} {}\n", head_commit_sha, capabilities);
    let want_length = format!("{:04x}", want_line.len() + 4);  // Adding 4 for the length itself

    // Format the request body for the `git-upload-pack` request.
    let request_body = format!(
        "{}{}0000",   // Send a pkt-line flush (0000) to properly terminate the request
        want_length, want_line
    );

    println!("Request body:\n{}", request_body);  // Debug: Print the request body

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

    // Check the response status
    let status = response.status();
    println!("Response status: {}", status);

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "Unable to fetch response body".to_string());
        return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to fetch packfile: HTTP status {}. Response body: {}", status, body)));
    }

    // Handle chunked transfer encoding
    let mut pack_data = Vec::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to read chunk: {}", err))
        })?;
        pack_data.extend(&chunk);  // Collect all chunks
    }

    println!("Downloaded packfile size: {} bytes", pack_data.len());

    if pack_data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "Downloaded packfile is empty"));
    }

    Ok(pack_data)
}

// Store the downloaded packfile in the .git/objects/pack directory
fn store_packfile(target_dir: &str, pack_data: Vec<u8>) -> io::Result<()> {
    let pack_dir = format!("{}/.git/objects/pack", target_dir);
    fs::create_dir_all(&pack_dir)?;

    let pack_file_path = format!("{}/packfile.pack", pack_dir);
    let mut pack_file = fs::File::create(&pack_file_path)?;
    pack_file.write_all(&pack_data)?;

    println!("Packfile stored at: {}", pack_file_path);
    Ok(())
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

// Verifies the repository after packfiles are downloaded
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

// Parse the refs response using the Git Smart HTTP protocol
fn parse_refs(refs_data: &[u8]) -> Option<String> {
    let refs_str = String::from_utf8_lossy(refs_data);

    // Debug: Print the entire refs response for analysis
    println!("Raw refs data: {}", refs_str);

    let mut head_ref: Option<String> = None;
    let mut branch_sha: Option<String> = None;
    let mut processing_refs = false; // Set to true when we start processing refs

    for line in refs_str.lines() {
        // Skip lines that are only "0000" (pkt-line flush marker)
        if line == "0000" {
            continue;
        }

        // Strip the first 4 characters (length prefix) from each line
        let line_content = &line[4..];

        // Handle the first pkt-line: `# service=git-upload-pack`
        if line_content.starts_with("# service=git-upload-pack") {
            println!("Found service announcement: {}", line_content);
            processing_refs = true; // Now we will process the ref discovery
            continue;
        }

        // Start processing refs after the service announcement
        if processing_refs {
            // The line should contain SHA-1, ref, and possibly capabilities
            if line_content.contains("symref=HEAD") {
                // Handle the symbolic HEAD ref (e.g., symref=HEAD:refs/heads/master)
                if let Some(symref_part) = line_content.split("symref=HEAD:").nth(1) {
                    let symref = symref_part.split_whitespace().next().unwrap_or("").trim();
                    println!("Found symbolic HEAD ref pointing to: {}", symref);
                    head_ref = Some(symref.to_string());
                }
            } else {
                // Split by NUL (`\0`) to separate ref from capabilities
                let parts: Vec<&str> = line_content.split('\0').collect();
                let ref_info = parts[0]; // This is the part before the capabilities

                // Split by space to separate SHA-1 from ref name
                let ref_parts: Vec<&str> = ref_info.split_whitespace().collect();
                if ref_parts.len() == 2 {
                    let sha = ref_parts[0];
                    let ref_name = ref_parts[1];

                    // Debug: Print the extracted ref and SHA
                    println!("Found ref: {}, SHA: {}", ref_name, sha);

                    // Match the ref_name with the head_ref (e.g., refs/heads/master)
                    if let Some(ref head_ref_val) = head_ref {
                        if ref_name == head_ref_val && sha.len() == 40 {
                            println!("Matched symbolic HEAD ref {} to SHA: {}", ref_name, sha);
                            branch_sha = Some(sha.to_string());
                        }
                    }
                }
            }
        }
    }

    // Return the branch SHA if found
    if let Some(sha) = branch_sha {
        return Some(sha);
    }
    eprintln!("HEAD ref not found.");
    None
}
