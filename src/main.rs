use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;
use flate2::read::ZlibDecoder;

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
        _ => {
            println!("unknown command: {}", args[1]);
        }
    }
}

// Function to decode and print the blob content from the .git/objects directory
fn print_blob_content(blob_sha: &str) -> std::io::Result<()> {
    if blob_sha.len() < 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid blob SHA"));
    }

    // First two characters form the directory
    let dir = &blob_sha[0..2];
    // Remaining characters form the file name
    let file = &blob_sha[2..];

    let object_path = format!(".git/objects/{}/{}", dir, file);

    // Check if the object file exists
    if !Path::new(&object_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Object not found"));
    }

    // Read the compressed object file
    let compressed_data = fs::read(&object_path)?;

    // Decompress using zlib
    let mut decoder = ZlibDecoder::new(&compressed_data[..]);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    // Git objects are stored in the format: "<type> <size>\0<content>"
    if let Some(null_pos) = decompressed_data.iter().position(|&b| b == 0) {
        let content = &decompressed_data[null_pos + 1..];
        println!("{}", String::from_utf8_lossy(content));
    } else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid object format"));
    }

    Ok(())
}
