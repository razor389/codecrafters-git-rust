use std::fs;
use std::io::{self, Write, Read};
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

// Store the downloaded packfile and index it manually
pub fn store_packfile(target_dir: &str, pack_data: Vec<u8>) -> io::Result<()> {
    let pack_dir = format!("{}/.git/objects/pack", target_dir);
    fs::create_dir_all(&pack_dir)?;

    // Step 1: Write the packfile to disk
    let pack_file_path = format!("{}/packfile.pack", pack_dir);
    let mut pack_file = fs::File::create(&pack_file_path)?;
    pack_file.write_all(&pack_data)?;

    println!("Packfile stored at: {}", pack_file_path);

    // Debug: Log the size of the downloaded packfile
    println!("Packfile downloaded and stored at: {} (size: {} bytes)", pack_file_path, pack_data.len());

    // Step 2: Validate and index the packfile
    println!("Starting packfile validation...");
    index_packfile(pack_data, &pack_dir)?;

    Ok(())
}

// Validate the packfile and extract its contents
fn validate_packfile(pack_data: &[u8]) -> io::Result<()> {
    // Debug: Log the first few bytes of the packfile
    println!("Validating packfile... First 16 bytes: {:?}", &pack_data[..16.min(pack_data.len())]);

    // The first 4 bytes should be "PACK"
    if &pack_data[0..4] != b"PACK" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packfile header"));
    }

    // The next 4 bytes are the version number
    let version = u32::from_be_bytes([pack_data[4], pack_data[5], pack_data[6], pack_data[7]]);
    if version != 2 && version != 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported packfile version"));
    }

    // The next 4 bytes are the number of objects
    let num_objects = u32::from_be_bytes([pack_data[8], pack_data[9], pack_data[10], pack_data[11]]);
    println!("Packfile contains {} objects", num_objects);

    Ok(())
}

// Decompress an individual object using zlib
fn decompress_object(compressed_data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();

    match decoder.read_to_end(&mut decompressed_data) {
        Ok(_) => {
            // Print the first 100 bytes of the decompressed data for debugging
            println!("Decompressed object successfully: size = {}", decompressed_data.len());
            println!("Decompressed data (first 100 bytes): {:?}", &decompressed_data[..100.min(decompressed_data.len())]);

            Ok(decompressed_data)
        },
        Err(err) => {
            println!("Error decompressing object: {:?}", err);
            Err(io::Error::new(io::ErrorKind::InvalidInput, format!("corrupt deflate stream: {:?}", err)))
        }
    }
}


fn index_packfile(pack_data: Vec<u8>, output_dir: &str) -> io::Result<()> {
    validate_packfile(&pack_data)?;

    let mut offset = 12; // Skip the 12-byte header
    let mut objects = Vec::new();

    // Calculate the limit, excluding the last 20 bytes for the SHA-1 checksum
    let packfile_data_len = pack_data.len();
    let packfile_data_end = packfile_data_len - 20; // Skip the last 20 bytes (SHA-1 checksum)

    println!("Starting to parse objects in the packfile...");

    while offset < packfile_data_end {
        // Ensure we don't go out of bounds
        if offset >= packfile_data_len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Reached unexpected end of packfile"));
        }

        println!("Current offset: {}", offset); // Log current position

        let obj_offset = offset;

        // Parse the object header (size, header_len, and type)
        let (obj_size, obj_header_len, obj_type) = match parse_object_header(&pack_data[offset..]) {
            Ok((size, header_len, obj_type)) => {
                println!("Parsed object header at offset {}: size = {}, header_len = {}, type = {}", obj_offset, size, header_len, obj_type);
                (size, header_len, obj_type)
            },
            Err(err) => {
                println!("Failed to parse object header at offset {}: {}", obj_offset, err);
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse object header: {}", err)));
            }
        };

        offset += obj_header_len;

        match obj_type {
            1 => println!("Object is a commit"),
            2 => println!("Object is a tree"),
            3 => println!("Object is a blob"),
            4 => println!("Object is a tag"),
            6 => {
                println!("Object is an OFS_DELTA (delta object by offset)");
                // Implement logic to handle OFS_DELTA (offset delta)
                // This will involve locating the base object and applying the delta to it
            },
            7 => {
                println!("Object is a REF_DELTA (delta object by reference)");
                // Implement logic to handle REF_DELTA (delta object by reference)
                // This will involve locating the base object using its SHA-1 and applying the delta
            },
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unknown object type: {}", obj_type)));
            }
        }

        // Check if we have enough bytes remaining to read the object
        if offset + obj_size > packfile_data_end {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!(
                "Not enough bytes to read object data (remaining: {}, required: {}, offset: {}, obj_size: {})",
                packfile_data_end - offset,
                obj_size,
                offset,
                obj_size
            )));
        }

        // Read and decompress object data (only for non-delta objects)
        if obj_type < 6 {
            let compressed_data = &pack_data[offset..offset + obj_size];
            println!("Compressed data (first 100 bytes) at offset {}: {:?}", offset, &compressed_data[..100.min(compressed_data.len())]);

            // Decompress the object data
            let decompressed_data = match decompress_object(compressed_data) {
                Ok(data) => data,
                Err(err) => {
                    println!("Error decompressing object at offset {}: {:?}", offset, err);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Failed to decompress object: {:?}", err)));
                }
            };

            println!("Decompressed object at offset {}: size = {}", obj_offset, decompressed_data.len());

            // Store the object offset and its decompressed data
            objects.push((obj_offset, decompressed_data));
        } else {
            // Handle delta objects later
            // For now, let's just advance the offset by the object size
            println!("Skipping delta object at offset {}", offset);
        }

        // Move to the next object
        offset += obj_size;
        println!("Moved to next object, new offset: {}", offset);
    }

    // Validate the packfile checksum (SHA-1)
    validate_packfile_checksum(&pack_data)?;

    // Write the index file based on object offsets and SHA-1 hashes
    println!("Finished parsing objects. Writing the index file...");
    write_packfile_index(objects, output_dir)?;

    println!("Packfile indexed successfully.");
    Ok(())
}


// Function to validate the SHA-1 checksum at the end of the packfile
fn validate_packfile_checksum(pack_data: &[u8]) -> io::Result<()> {
    let data_without_checksum = &pack_data[..pack_data.len() - 20];
    let expected_checksum = &pack_data[pack_data.len() - 20..];

    let mut hasher = Sha1::new();
    hasher.update(data_without_checksum);
    let calculated_checksum = hasher.finalize();

    if &calculated_checksum[..] != expected_checksum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Packfile checksum does not match"));
    }

    println!("Packfile checksum is valid.");
    Ok(())
}


fn parse_object_header(data: &[u8]) -> io::Result<(usize, usize, u8)> {
    let mut header_len = 0;
    #[allow(unused_assignments)]
    let mut size = 0;
    let mut shift = 0;

    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Object header is empty"));
    }

    // First byte holds type and size bits
    let mut c = data[header_len];
    let obj_type = (c >> 4) & 0x7; // 3 bits for type
    size = (c & 0x0F) as usize;    // 4 bits for size
    header_len += 1;

    // Parse size (varint encoding)
    while c & 0x80 != 0 {
        if header_len >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Object header exceeds data length"));
        }
        c = data[header_len];
        size |= ((c & 0x7F) as usize) << shift;
        shift += 7;
        header_len += 1;
    }

    // Object types:
    // 1 = commit, 2 = tree, 3 = blob, 4 = tag, 6 = OFS_DELTA, 7 = REF_DELTA
    println!("Object type: {}, size: {}, header_len: {}", obj_type, size, header_len);

    Ok((size, header_len, obj_type))
}



// Write the packfile index (.idx)
fn write_packfile_index(objects: Vec<(usize, Vec<u8>)>, output_dir: &str) -> io::Result<()> {
    let idx_file_path = format!("{}/packfile.idx", output_dir);
    let mut idx_file = fs::File::create(&idx_file_path)?;

    // Write the index header (magic number + version)
    idx_file.write_all(&[0xff, 0x74, 0x4f, 0x63])?; // Magic number
    idx_file.write_all(&[0, 0, 0, 2])?; // Version number

    let mut fanout = [0u32; 256];
    let mut sha1_list = Vec::new();
    let mut offsets = Vec::new();

    // For each object, compute SHA-1 hash and determine its offset
    for (offset, object_data) in objects {
        let sha1 = compute_sha1_hash(&object_data);
        fanout[sha1[0] as usize] += 1;
        sha1_list.push(sha1);
        offsets.push(offset);
    }

    // Compute the fanout table
    for i in 1..256 {
        fanout[i] += fanout[i - 1];
    }

    // Write the fanout table
    for entry in &fanout {
        idx_file.write_all(&entry.to_be_bytes())?;
    }

    // Sort and write the SHA-1 hashes
    sha1_list.sort();
    for sha1 in sha1_list {
        idx_file.write_all(&sha1)?;
    }

    // Write the object offsets
    for offset in offsets {
        idx_file.write_all(&(offset as u32).to_be_bytes())?;
    }

    Ok(())
}

// Compute the SHA-1 hash of the object
fn compute_sha1_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
