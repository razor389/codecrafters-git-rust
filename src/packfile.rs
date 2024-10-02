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
    println!("Validating packfile... First 100 bytes: {:?}", &pack_data[..100.min(pack_data.len())]);

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

fn index_packfile(pack_data: Vec<u8>, output_dir: &str) -> io::Result<()> {
    validate_packfile(&pack_data)?;

    let mut offset = 12; // Skip the 12-byte PACK header
    let packfile_data_end = pack_data.len() - 20; // Exclude SHA-1 checksum at the end
    let mut objects = Vec::new();

    println!("Starting to parse objects in the packfile...");

    while offset < packfile_data_end {
        println!("Current offset: {}", offset);

        let obj_offset = offset;

        // Parse the object header (get uncompressed size, header length, and type)
        let (obj_size, obj_header_len, obj_type) = match parse_object_header(&pack_data[offset..]) {
            Ok((size, header_len, obj_type)) => {
                println!(
                    "Parsed object header at offset {}: size = {}, header_len = {}, type = {}",
                    obj_offset, size, header_len, obj_type
                );
                (size, header_len, obj_type)
            }
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse object header: {}", err)
                ));
            }
        };

        offset += obj_header_len; // Move past the header

        // Get the compressed data starting at the current offset
        let compressed_data = &pack_data[offset..];
        // println!(
        //     "Compressed data range: offset = {}, length = {}",
        //     offset,
        //     compressed_data.len()
        // );

        // Decompress the object data and track how many bytes were consumed in the compressed stream
        match decompress_object_with_consumed(compressed_data) {
            Ok((decompressed_data, bytes_consumed)) => {
                // Ensure decompressed data matches the size in the header
                if decompressed_data.len() != obj_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Decompressed object size mismatch at offset {}: expected {}, got {}",
                            obj_offset, obj_size, decompressed_data.len()
                        ),
                    ));
                }

                println!(
                    "Decompressed object at offset {}: decompressed size = {}, bytes consumed = {}",
                    obj_offset,
                    decompressed_data.len(),
                    bytes_consumed
                );

                // Store the decompressed object
                objects.push((obj_offset, decompressed_data));

                // Move to the next object based on the number of compressed bytes consumed
                offset += bytes_consumed;
            }
            Err(err) => {
                println!("Error decompressing object at offset {}: {:?}", offset, err);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to decompress object: {:?}", err)
                ));
            }
        }

        println!("Moved to next object, new offset: {}", offset);
    }

    // Validate the packfile checksum
    validate_packfile_checksum(&pack_data)?;

    // Write the index file based on object offsets and SHA-1 hashes
    write_packfile_index(objects, output_dir)?;

    println!("Packfile indexed successfully.");
    Ok(())
}

fn decompress_object_with_consumed(compressed_data: &[u8]) -> io::Result<(Vec<u8>, usize)> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();

    // Decompress the data into `decompressed_data`
    let result = decoder.read_to_end(&mut decompressed_data);
    
    match result {
        Ok(_) => {
            // Calculate how many bytes were consumed from the compressed stream
            let bytes_consumed = decoder.total_in() as usize;
            Ok((decompressed_data, bytes_consumed))
        }
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
    }
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
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Object header is empty"));
    }

    let mut header_len = 1;  // The first byte is always part of the header
    let first_byte = data[0];

    // Extract object type (bits 4-6) from the first byte
    let obj_type = (first_byte >> 4) & 0x07;

    // Extract initial size (bits 0-3) from the first byte
    let mut size = (first_byte & 0x0F) as usize;
    let mut shift = 4;  // First 4 bits already used for size

    println!("Parsing object header...");
    println!("First byte: {:08b} (binary), 0x{:02x} (hex)", first_byte, first_byte);
    println!("Initial object type: {}", obj_type);
    println!("Initial size (from 4 bits): {}", size);

    // Check if the size is encoded across multiple bytes (if bit 7 of the first byte is set)
    let mut index = 1;
    if (first_byte & 0x80) != 0 {
        // The first byte has MSB set, so continue reading additional bytes for size
        while index < data.len() {
            let next_byte = data[index];
            println!("Byte {}: {:08b} (binary), 0x{:02x} (hex)", index, next_byte, next_byte);
            size |= ((next_byte & 0x7F) as usize) << shift;  // Extract the next 7 bits for the size
            shift += 7;  // Increment shift for the next 7 bits
            index += 1;

            // Stop when we encounter a byte with MSB (bit 7) unset
            if next_byte & 0x80 == 0 {
                break;
            }

            // Ensure we don't exceed the data length
            if index >= data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Object header exceeds data length"));
            }
        }
    }

    header_len = index;
    println!("Parsed object header length: {}", header_len);
    println!("Final size: {}, object type: {}", size, obj_type);

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
