use std::fs;
use std::io::{self, Write, Read};
use crate::object_headers::GitObjectHeader;
use std::path::Path;


/// Define a Hash type to represent a 20-byte SHA-1 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash([u8; 20]);

use std::hash::{Hash as StdHash, Hasher};

impl StdHash for Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the bytes of the SHA-1 hash
        self.0.hash(state);
    }
}

impl Hash {
    /// Create a new `Hash` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() == 20 {
            let mut array = [0u8; 20];
            array.copy_from_slice(bytes);
            Ok(Hash(array))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid hash length"))
        }
    }

    /// Convert the `Hash` into its hexadecimal string representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Convert the `Hash` into its raw byte representation.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

/// Enum representing different types of Git objects.
#[derive(Debug, Clone)]
pub enum GitObject {
    Blob(Vec<u8>),
    Tree(Vec<GitTreeEntry>),
    Commit(GitCommit),
}

/// Struct representing an entry in a Git tree object.
#[derive(Debug, Clone)]
pub struct GitTreeEntry {
    pub mode: String,
    pub name: String,
    pub object: Hash, // Object ID (SHA-1 hash)
}

#[derive(Debug, Clone)]
pub struct GitCommit {
    pub tree: Hash,               // The root tree object ID
    pub parent: Option<Hash>,      // The parent commit ID (None if first commit)
    pub author_name: String,       // Author name
    pub author_email: String,      // Author email
    pub committer_name: String,    // Committer name
    pub committer_email: String,   // Committer email
    pub timestamp: u64,            // Commit timestamp (seconds since UNIX epoch)
    pub timezone: String,          // Timezone offset (e.g. +0000)
    pub message: String,           // Commit message
}


impl GitObject {
    /// Write the Git object to a file in the `.git/objects` directory.
    pub fn write(&self) -> io::Result<()> {
        // Use the hash to generate the object ID
        let object_id = self.hash();
        let object_id_hex = object_id.to_hex();  // Convert Hash to hex

        // The first two characters of the hash form the directory name
        let object_path = format!(".git/objects/{}", &object_id_hex[..2]);  
        let object_file = format!("{}/{}", object_path, &object_id_hex[2..]); // Remaining part forms the filename
        //println!("writing to {}", object_file);
        // Ensure directory exists
        fs::create_dir_all(object_path)?;
        
        // Serialize and compress the object data (Git uses zlib compression)
        let data = self.serialize();
        let compressed_data = compress(&data)?;

        // Write compressed data to file
        let mut file = fs::File::create(object_file)?;
        file.write_all(&compressed_data)?;

        Ok(())
    }

    /// Read a Git object from the `.git/objects` directory.
    pub fn read(object_id: &str) -> io::Result<GitObject> {
        let object_path = format!(".git/objects/{}/{}", &object_id[..2], &object_id[2..]);
        //println!("trying to read from {}", object_path);
        // Read and decompress the object data
        let mut file = fs::File::open(object_path)?;
        let mut compressed_data = Vec::new();
        file.read_to_end(&mut compressed_data)?;
        let data = decompress(&compressed_data)?;

        // Deserialize the object from the raw data
        GitObject::deserialize(&data)
    }

    /// Read a Git object from the `.git/objects` directory using the object's hash.
    pub fn read_by_hash(hash: Hash) -> io::Result<Self> {
        // Convert hash to hexadecimal for file lookup
        let object_id_hex = hash.to_hex();
        
        // The first two characters of the hash form the directory name
        let object_path = format!(".git/objects/{}/{}", &object_id_hex[..2], &object_id_hex[2..]);
        //println!("Reading from {}", object_path);

        // Read the compressed object data from the file
        let mut file = fs::File::open(object_path)?;
        let mut compressed_data = Vec::new();
        file.read_to_end(&mut compressed_data)?;
        
        // Decompress the object data
        let data = decompress(&compressed_data)?;

        // Deserialize the data into a GitObject
        GitObject::deserialize(&data)
    }
    /// Get the length of the actual data in the object, excluding the header.
    #[allow(dead_code)]
    pub fn data_len(&self) -> usize {
        match self {
            GitObject::Blob(data) => data.len(), // Blob is just raw data
            GitObject::Tree(_) | GitObject::Commit(_) => {
                // For Tree and Commit, we parse the serialized object to extract the size
                let serialized = self.serialize();
                // Deserialize and extract the content after the header
                let (header, _) = GitObjectHeader::from_bytes(&serialized).unwrap();
                header.size  // Return the size specified in the header
            }
        }
    }
    /// Serialize the Git object into raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            GitObject::Blob(data) => {
                let header = format!("blob {}", data.len());
                let mut result = Vec::from(header.as_bytes());
                result.push(0); // Add the null byte explicitly
                result.extend_from_slice(data);
                result
            }
            GitObject::Tree(entries) => {
                let mut result = Vec::new();
                
                for entry in entries {
                    let mut entry_data = format!("{} {}", entry.mode, entry.name).into_bytes();
                    entry_data.push(0);
                    result.extend_from_slice(&entry_data);
                    result.extend_from_slice(entry.object.as_bytes()); // Append the raw 20-byte SHA-1 hash
                }
                let header = format!("tree {}", result.len());
                
                let mut full_result = Vec::from(header.as_bytes());
                full_result.push(0); // Add the null byte explicitly
                //println!("Tree header: {:?}", full_result);
                //println!("Total serialized tree size: {}", result.len());
                full_result.extend(result);
                full_result
            }
            GitObject::Commit(commit) => {
                let mut result = Vec::new();
                
                // Tree object SHA
                result.extend_from_slice(format!("tree {}\n", commit.tree.to_hex()).as_bytes());

                // Parent commit SHA if exists
                if let Some(parent) = &commit.parent {
                    result.extend_from_slice(format!("parent {}\n", parent.to_hex()).as_bytes());
                }

                // Author and Committer information with timestamp and timezone
                result.extend_from_slice(format!(
                    "author {} <{}> {} {}\n",
                    commit.author_name, commit.author_email, commit.timestamp, commit.timezone
                ).as_bytes());

                result.extend_from_slice(format!(
                    "committer {} <{}> {} {}\n",
                    commit.committer_name, commit.committer_email, commit.timestamp, commit.timezone
                ).as_bytes());

                // Add an empty line before the commit message
                result.push(b'\n');

                // Commit message
                result.extend_from_slice(commit.message.as_bytes());

                let header = format!("commit {}\0", result.len());
                [header.as_bytes(), &result].concat()
            }
        }
    }

    /// Deserialize raw bytes into a Git object.
    pub fn deserialize(data: &[u8]) -> io::Result<GitObject> {
        // Parse the header to determine the object type and size
        let (header, content) = GitObjectHeader::from_bytes(data)?;

        match header.object_type.as_str() {
            "blob" => {
                if content.len() == header.size {
                    Ok(GitObject::Blob(content.to_vec()))
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "Blob size mismatch"))
                }
            }
            "tree" => {
                let tree_entries = GitObject::parse_tree_entries(content)?;
                Ok(GitObject::Tree(tree_entries))
            }
            "commit" => {
                let commit = GitObject::parse_commit(content)?;
                Ok(GitObject::Commit(commit))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown object type")),
        }
    }

    /// Parse tree entries from raw data.
    pub fn parse_tree_entries(data: &[u8]) -> io::Result<Vec<GitTreeEntry>> {
        let mut entries = Vec::new();
        let mut i = 0;
        while i < data.len() {
            // Read mode (until space)
            let mode_end = data[i..].iter().position(|&b| b == b' ').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid tree entry: no mode")
            })?;
            let mode = std::str::from_utf8(&data[i..i + mode_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid mode"))?
                .to_string();
            i += mode_end + 1;

            // Read name (until null byte)
            let name_end = data[i..].iter().position(|&b| b == 0).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid tree entry: no name")
            })?;
            let name = std::str::from_utf8(&data[i..i + name_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid name"))?
                .to_string();
            i += name_end + 1;

            // Read the 20-byte object ID (SHA-1)
            let object = Hash::from_bytes(&data[i..i + 20])?;
            i += 20;

            // Add entry
            entries.push(GitTreeEntry { mode, name, object });
        }
        //println!("tree entries: {:?}", entries);
        Ok(entries)
    }
    
    pub fn parse_commit(data: &[u8]) -> io::Result<GitCommit> {
        let content = std::str::from_utf8(data)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid commit data"))?;
        
        let mut tree = None;
        let mut parent = None;
        let mut author_name = String::new();
        let mut author_email = String::new();
        let mut committer_name = String::new();
        let mut committer_email = String::new();
        let mut timestamp = 0;
        let mut timezone = String::new();
        #[allow(unused_assignments)]
        let mut message = String::new();
    
        let mut lines = content.lines();
        // Step 1: Parse the metadata (tree, parent, author, committer)
        while let Some(line) = lines.next() {
            if line.is_empty() {
                // Stop parsing metadata when we hit the blank line before the commit message
                break;
            }
            if let Some(tree_hash) = line.strip_prefix("tree ") {
                tree = Some(Hash::from_bytes(
                    &hex::decode(tree_hash).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
                )?);
            } else if let Some(parent_hash) = line.strip_prefix("parent ") {
                parent = Some(Hash::from_bytes(
                    &hex::decode(parent_hash).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
                )?);
            } else if let Some(author_info) = line.strip_prefix("author ") {
                // Example format: "author John Doe <john@example.com> 1609459200 +0000"
                let parts: Vec<&str> = author_info.split_whitespace().collect();
                if parts.len() >= 5 {
                    author_name = parts[0..parts.len() - 4].join(" ");
                    author_email = parts[parts.len() - 4].trim_start_matches('<').trim_end_matches('>').to_string();
                    timestamp = parts[parts.len() - 2].parse::<u64>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid timestamp in author field")
                    })?;
                    timezone = parts[parts.len() - 1].to_string();
                }
            } else if let Some(committer_info) = line.strip_prefix("committer ") {
                // Example format: "committer John Doe <john@example.com> 1609459200 +0000"
                let parts: Vec<&str> = committer_info.split_whitespace().collect();
                if parts.len() >= 5 {
                    committer_name = parts[0..parts.len() - 4].join(" ");
                    committer_email = parts[parts.len() - 4].trim_start_matches('<').trim_end_matches('>').to_string();
                    // Use the same timestamp and timezone as the author for simplicity
                    timestamp = parts[parts.len() - 2].parse::<u64>().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid timestamp in committer field")
                    })?;
                    timezone = parts[parts.len() - 1].to_string();
                }
            }
        }
    
        // Step 2: Capture the commit message (everything after the blank line)
        message = lines.collect::<Vec<&str>>().join("\n");
    
        let commit = GitCommit {
            tree: tree.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing tree"))?,
            parent,
            author_name,
            author_email,
            committer_name,
            committer_email,
            timestamp,
            timezone,
            message,
        };
        //println!("{:?}", commit);
        Ok(commit)
    }
    
    
    /// Compute the hash (SHA-1) of the object data.
    pub fn hash(&self) -> Hash {
        use sha1::{Sha1, Digest};

        let data = self.serialize();
        let mut hasher = Sha1::new();
        hasher.update(&data);
        Hash::from_bytes(&hasher.finalize()).unwrap()
    }
}


/// Recursively reads the current working directory and constructs tree entries.
pub fn read_current_directory() -> io::Result<Vec<GitTreeEntry>> {
    let mut entries = Vec::new();
    let current_dir = Path::new(".");

    // Walk through the current directory recursively
    for entry in fs::read_dir(current_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name().into_string().unwrap();

        if path.is_file() {
            // Hash the file and get its SHA-1 hash
            let file_hash = hash_file(&path)?;

            // Create a tree entry for the file
            let tree_entry = GitTreeEntry {
                mode: "100644".to_string(), // Regular file mode
                name: file_name,
                object: file_hash,
            };

            entries.push(tree_entry);
        } else if path.is_dir() && file_name != ".git" {
            // Recursively handle directories (excluding .git directory)
            let dir_hash = write_tree_for_directory(&path)?;

            // Create a tree entry for the directory
            let tree_entry = GitTreeEntry {
                mode: "40000".to_string(), // Directory mode
                name: file_name,
                object: dir_hash,
            };

            entries.push(tree_entry);
        }
    }
    // Sort entries lexicographically by name
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(entries)
}

/// Hash a file and return its SHA-1 hash.
fn hash_file(path: &Path) -> io::Result<Hash> {
    // Read the file content
    let content = fs::read(path)?;

    // Create a blob object
    let blob = GitObject::Blob(content);

    // Get the SHA-1 hash of the blob
    let hash = blob.hash();

    // Write the blob to the .git/objects directory
    blob.write()?;

    Ok(hash)
}

/// Recursively writes a tree object for a directory and returns its SHA-1 hash.
fn write_tree_for_directory(path: &Path) -> io::Result<Hash> {
    let entries = read_directory(path)?;

    // Create a tree object with these entries
    let tree = GitObject::Tree(entries);

    // Get the SHA-1 hash of the tree
    let hash = tree.hash();

    // Write the tree object to the .git/objects directory
    tree.write()?;

    Ok(hash)
}

/// Recursively read a directory and return a list of tree entries.
fn read_directory(path: &Path) -> io::Result<Vec<GitTreeEntry>> {
    let mut entries = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name().into_string().unwrap();

        if path.is_file() {
            let file_hash = hash_file(&path)?;

            let tree_entry = GitTreeEntry {
                mode: "100644".to_string(),
                name: file_name,
                object: file_hash,
            };

            entries.push(tree_entry);
        } else if path.is_dir() && file_name != ".git" {
            let dir_hash = write_tree_for_directory(&path)?;

            let tree_entry = GitTreeEntry {
                mode: "40000".to_string(),
                name: file_name,
                object: dir_hash,
            };

            entries.push(tree_entry);
        }
    }
    // Sort entries lexicographically by name
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(entries)
}

/// Placeholder function for compressing data (Git uses zlib compression)
fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Placeholder function for decompressing data (Git uses zlib compression)
pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Cursor;

    let mut decoder = ZlibDecoder::new(Cursor::new(data));
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;
    Ok(decompressed_data)
}
