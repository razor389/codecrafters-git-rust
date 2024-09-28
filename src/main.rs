use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::fs::File;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Sha1, Digest};

fn main() {
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
        let file_name_str = file_name.to_string_lossy();

        if file_name_str == ".git" {
            continue; // Skip the .git directory
        }

        if path.is_file() {
            // It's a file, create a blob and get the SHA-1
            let sha1 = create_blob(&path.to_string_lossy())?;
            let mode = "100644"; // Regular file mode

            // Append mode, name, and binary SHA-1 to the tree entry
            tree_entries.extend_from_slice(format!("{} {}", mode, file_name_str).as_bytes());
            tree_entries.push(0u8);  // Null byte separator
            tree_entries.extend_from_slice(&hex::decode(sha1).unwrap());  // Append 20-byte binary SHA-1
        } else if path.is_dir() {
            // It's a directory, recursively write tree and get the tree SHA-1
            let sha1 = write_tree_recursive(&path)?;
            let mode = "40000"; // Directory mode

            // Append mode, name, and binary SHA-1 to the tree entry
            tree_entries.extend_from_slice(format!("{} {}", mode, file_name_str).as_bytes());
            tree_entries.push(0u8);  // Null byte separator
            tree_entries.extend_from_slice(&hex::decode(sha1).unwrap());  // Append 20-byte binary SHA-1
        }
    }

    // Create the tree header
    let tree_header = format!("tree {}\0", tree_entries.len());
    let mut full_data = Vec::new();
    full_data.extend(tree_header.as_bytes());
    full_data.extend(tree_entries);

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
