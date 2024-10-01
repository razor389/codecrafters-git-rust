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

    // Step 2: Parse and index the packfile manually
    index_packfile(pack_data, &pack_dir)?;

    Ok(())
}

// Validate the packfile and extract its contents
fn validate_packfile(pack_data: &[u8]) -> io::Result<()> {
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
    decoder.read_to_end(&mut decompressed_data)?;
    Ok(decompressed_data)
}

// Parse and index the objects in the packfile
fn index_packfile(pack_data: Vec<u8>, output_dir: &str) -> io::Result<()> {
    validate_packfile(&pack_data)?;

    let mut offset = 12; // Skip the 12-byte header
    let mut objects = Vec::new();

    // Parse the objects in the packfile
    while offset < pack_data.len() - 20 { // Leave out the final SHA-1 checksum
        let obj_offset = offset;

        // Parse the object header (size and type)
        let (obj_size, obj_header_len) = parse_object_header(&pack_data[offset..])?;
        offset += obj_header_len;

        // Decompress the object data
        let compressed_data = &pack_data[offset..offset + obj_size];
        let decompressed_data = decompress_object(compressed_data)?;

        // Store the object offset and its decompressed data
        objects.push((obj_offset, decompressed_data));

        // Move to the next object
        offset += obj_size;
    }

    // Write the index file based on object offsets and SHA-1 hashes
    write_packfile_index(objects, output_dir)?;

    println!("Packfile indexed successfully.");
    Ok(())
}

// Parse an individual object's header (returns size and header length)
fn parse_object_header(data: &[u8]) -> io::Result<(usize, usize)> {
    let mut header_len = 0;
    #[allow(unused_assignments)]
    let mut size = 0;
    let mut shift = 0;

    // Parse the type (first 3 bits) and size (remaining bits)
    let c = data[header_len];
    size = (c & 0b1111) as usize; // Size in the last 4 bits
    header_len += 1;

    // If the size spans multiple bytes
    while c & 0x80 != 0 {
        let c = data[header_len];
        size |= ((c & 0x7f) as usize) << shift;
        shift += 7;
        header_len += 1;
    }

    Ok((size, header_len))
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
