use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::fs::File;
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
        println!("{}", String::from_utf8_lossy(content));
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
