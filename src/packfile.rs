use std::{collections::HashMap, fs::File, io::{self, Error, ErrorKind, Read, Seek, SeekFrom}};
use flate2::read::ZlibDecoder;
use crate::objects::{GitCommit, GitObject, Hash};

const TYPE_BITS: u8 = 3;
const VARINT_ENCODING_BITS: u8 = 7;
const TYPE_BYTE_SIZE_BITS: u8 = VARINT_ENCODING_BITS - TYPE_BITS;
const VARINT_CONTINUE_FLAG: u8 = 1 << VARINT_ENCODING_BITS;
/// Constants used in the delta application process
const COPY_INSTRUCTION_FLAG: u8 = 1 << 7;
const COPY_OFFSET_BYTES: u8 = 4;
const COPY_SIZE_BYTES: u8 = 3;
const COPY_ZERO_SIZE: usize = 0x10000;


fn make_error(message: &str) -> Error {
    Error::new(ErrorKind::Other, message)
}

fn read_bytes<R: Read, const N: usize>(stream: &mut R) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_size_encoding<R: Read>(stream: &mut R) -> io::Result<usize> {
    let mut value = 0;
    let mut length = 0;
    loop {
        let (byte_value, more_bytes) = read_varint_byte(stream)?;
        value |= (byte_value as usize) << length;
        if !more_bytes {
            return Ok(value)
        }

        length += VARINT_ENCODING_BITS;
    }
}

fn read_varint_byte<R: Read>(stream: &mut R) -> io::Result<(u8, bool)> {
    let [byte] = read_bytes(stream)?;
    let value = byte & !VARINT_CONTINUE_FLAG;
    let more_bytes = byte & VARINT_CONTINUE_FLAG != 0;
    Ok((value, more_bytes))
}

fn keep_bits(value: usize, bits: u8) -> usize {
    value & ((1 << bits) - 1)
}

fn read_type_and_size<R: Read>(stream: &mut R) -> io::Result<(u8, usize)> {
    // Object type and uncompressed pack data size
    // are stored in a "size-encoding" variable-length integer.
    // Bits 4 through 6 store the type and the remaining bits store the size.
    let value = read_size_encoding(stream)?;
    let object_type = keep_bits(value >> TYPE_BYTE_SIZE_BITS, TYPE_BITS) as u8;
    let size = keep_bits(value, TYPE_BYTE_SIZE_BITS)
                | (value >> VARINT_ENCODING_BITS << TYPE_BYTE_SIZE_BITS);
    Ok((object_type, size))
}


fn read_offset_encoding<R: Read>(stream: &mut R) -> io::Result<u64> {
    // Like the object length, the offset for an OffsetDelta object
    // is stored in a variable number of bytes,
    // with the most significant bit of each byte indicating whether more bytes follow.
    // However, the object length encoding allows redundant values,
    // e.g. the 7-bit value [n] is the same as the 14- or 21-bit values [n, 0] or [n, 0, 0].
    // Instead, the offset encoding adds 1 to the value of each byte except the least significant one.
    // And just for kicks, the bytes are ordered from *most* to *least* significant.
    let mut value = 0;
    loop {
        let (byte_value, more_bytes) = read_varint_byte(stream)?;
        value = (value << VARINT_ENCODING_BITS) | byte_value as u64;
        if !more_bytes {
            return Ok(value)
        }

        value += 1;
    }
}

fn read_partial_int<R: Read>(stream: &mut R, bytes: u8, present_bytes: &mut u8) -> io::Result<usize> {
    let mut value = 0;
    for byte_index in 0..bytes {
        if *present_bytes & 1 != 0 {
            let [byte] = read_bytes(stream)?;
            value |= (byte as usize) << (byte_index * 8);
        }
        *present_bytes >>= 1;
    }
    Ok(value)
}

fn seek(file: &mut File, offset: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    Ok(())
}

fn get_offset(file: &mut File) -> io::Result<u64> {
    file.seek(SeekFrom::Current(0))
}

fn read_hash<R: Read>(stream: &mut R) -> io::Result<Hash> {
    let bytes: [u8; 20] = read_bytes(stream)?;
    Ok(Hash::from_bytes(&bytes)?)
}

// Reads the contents of a zlib stream from a file
// and ensures the decompressed contents have the correct size
fn read_zlib_stream(file: &mut File, size: usize) -> io::Result<Vec<u8>> {
    let offset = get_offset(file)?;
    let mut decompressed = ZlibDecoder::new(file);
    let mut contents = Vec::with_capacity(size);
    decompressed.read_to_end(&mut contents)?;
    // Reset the offset since ZlibDecoder uses BufReader,
    // which may consume extra bytes
    let zlib_end = offset + decompressed.total_in();
    seek(decompressed.into_inner(), zlib_end)?;
    if contents.len() != size {
        return Err(make_error("Incorrect decompressed size"))
    }

    Ok(contents)
}

/// Apply a delta instruction to a base object and write the result into `result`
fn apply_delta_instruction<R: Read>(
    stream: &mut R,
    base: &[u8],
    result: &mut Vec<u8>
) -> io::Result<bool> {
    // Read the delta instruction byte
    let instruction = match read_bytes(stream) {
        Ok([instruction]) => instruction,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(false),
        Err(err) => return Err(err),
    };

    if instruction & COPY_INSTRUCTION_FLAG == 0 {
        // Data instruction: the instruction byte specifies the number of data bytes to append
        if instruction == 0 {
            return Err(make_error("Invalid data instruction: appending 0 bytes is not allowed"));
        }

        let mut data = vec![0; instruction as usize];
        stream.read_exact(&mut data)?;
        result.extend_from_slice(&data);
    } else {
        // Copy instruction: copy bytes from the base object
        let mut nonzero_bytes = instruction;
        let offset = read_partial_int(stream, COPY_OFFSET_BYTES, &mut nonzero_bytes)?;
        let mut size = read_partial_int(stream, COPY_SIZE_BYTES, &mut nonzero_bytes)?;
        if size == 0 {
            size = COPY_ZERO_SIZE;
        }

        // Copy bytes from the base object
        let base_data = base.get(offset..(offset + size)).ok_or_else(|| {
            make_error("Invalid copy instruction: base object access out of bounds")
        })?;
        result.extend_from_slice(base_data);
    }
    Ok(true)
}

fn apply_delta<R: Read>(
    stream: &mut R,
    base: &GitObject
) -> io::Result<GitObject> {
    // Prepare a variable to store the serialized base contents
    let base_contents: Vec<u8>;
    let object_type: &str;

    // Unpack the base object contents and set the type for the new object
    match base {
        GitObject::Blob(contents) => {
            base_contents = contents.clone();  // Blobs are just raw contents
            object_type = "blob";
        }
        GitObject::Tree(_) => {
            base_contents = base.serialize();
            object_type = "tree";
        }
        GitObject::Commit(_) => {
            base_contents = base.serialize();
            object_type = "commit";
        }
    };

    // Decompress the delta and apply it to the base object
    let mut delta_stream = ZlibDecoder::new(stream);

    // Step 1: Read base size from delta (error check: it should match the base size)
    let base_size = read_size_encoding(&mut delta_stream)?;
    
    // Step 2: Check the base size against the actual base contents size
    let actual_base_content = match object_type {
        "blob" => {
            // Blobs don't have a header, we just check the content length directly
            &base_contents
        }
        "tree" | "commit" => {
            // For tree/commit, strip the header and check the content size
            let header_size = base_contents
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid header in base object"))? + 1;
            &base_contents[header_size..]
        }
        _ => return Err(make_error("Unknown object type")),
    };

    if actual_base_content.len() != base_size {
        println!("base contents size: {}", actual_base_content.len());
        println!("base size from encoding: {}", base_size);
        return Err(make_error("Incorrect base object length"));
    }

    // Step 3: Read the size of the resulting object after delta application
    let result_size = read_size_encoding(&mut delta_stream)?;
    let mut result = Vec::with_capacity(result_size);

    // Step 4: Apply delta instructions to transform the base object into the new object
    while apply_delta_instruction(&mut delta_stream, actual_base_content, &mut result)? {}

    if result.len() != result_size {
        return Err(make_error("Incorrect result size after applying delta"));
    }

    // Step 5: Generate a new header for the resulting object
    let new_header = match object_type {
        "blob" => format!("blob {}\0", result_size).into_bytes(),
        "tree" => format!("tree {}\0", result_size).into_bytes(),
        "commit" => format!("commit {}\0", result_size).into_bytes(),
        _ => return Err(make_error("Unknown object type")),
    };

    // Step 6: Concatenate the new header and the result data
    let full_object_data = [new_header, result].concat();

    // Step 7: Deserialize the resulting object
    GitObject::deserialize(&full_object_data)
}



/// Struct to represent a Git packfile
pub struct Packfile<'a> {
    file: &'a mut File,
    num_objects: u32, // Number of objects to unpack
}

impl<'a> Packfile<'a> {
    /// Create a new Packfile instance
    pub fn new(file: &'a mut File, num_objects: u32) -> Self {
        Packfile { file, num_objects }
    }

    fn read_type_and_size(&mut self) -> io::Result<(u8, usize)> {
        read_type_and_size(self.file)
    }

     /// Parse and unpack the packfile
     pub fn unpack_and_collect_commits(&mut self) -> io::Result<Vec<GitCommit>> {
        // Map of offsets to objects that were unpacked
        let mut read_objects: HashMap<u64, GitObject> = HashMap::new();
        let mut commits = Vec::new();
        for _ in 0..self.num_objects {
            // Step 1: Save the current offset
            let offset = get_offset(self.file)?;

            // Step 2: Read object type and size from the packfile
            let (object_type, size) = self.read_type_and_size()?;
            //println!("Object type: {}, Size: {}", object_type, size);

            // Step 3: Handle object types (1, 2, 3 are direct object types)
            let git_object = match object_type {
                1 => {
                    // Commit object
                    let decompressed_data = read_zlib_stream(self.file, size)?;
                    let commit = GitObject::parse_commit(&decompressed_data)?;
                    let commit_obj = GitObject::Commit(commit.clone());
                    println!("{:?}", commit_obj);
                    println!("serialized commit: {:?}", String::from_utf8_lossy(&commit_obj.serialize()));
                    commits.push(commit);
                    commit_obj
                }
                2 => {
                    // Tree object
                    let decompressed_data = read_zlib_stream(self.file, size)?;
                    GitObject::Tree(GitObject::parse_tree_entries(&decompressed_data)?)
                }
                3 => {
                    // Blob object
                    let decompressed_data = read_zlib_stream(self.file, size)?;
                    //println!("blob data: {:?}", String::from_utf8(decompressed_data.clone()));
                    GitObject::Blob(decompressed_data)
                }
                6 => {
                    // Offset delta object
                    println!("offset delta object");
                    // Step 1: Read the delta offset
                    let delta_offset = read_offset_encoding(self.file)?;

                    // Step 2: Calculate the base offset
                    let base_offset = offset.checked_sub(delta_offset).unwrap();

                    // Step 3: Save the current position (delta_start)
                    let delta_start = get_offset(self.file)?;

                    // Step 4: Retrieve the base object from read_objects map
                    let base_object = read_objects.get(&base_offset)
                        .ok_or_else(|| make_error("Base object not found for offset delta"))?;

                    // Step 5: Apply the delta to the base object
                    let object = apply_delta(self.file, base_object)?;

                    // Step 6: Seek back to delta_start (in case zlib decoder read extra bytes)
                    seek(self.file, delta_start)?;

                    // Step 7: Read the zlib stream (this ensures zlib is correctly processed)
                    read_zlib_stream(self.file, size)?;

                    // Return the object created from applying the delta
                    object
                }
                7 => {
                    // Hash delta object   
                    println!("hash delta object");

                    // Step 1: Read the base object's hash
                    let base_hash = read_hash(self.file)?;

                    // Step 2: Retrieve the base object by its hash
                    let base_object = GitObject::read_by_hash(base_hash)?;

                    // Step 3: Save the current position (delta_start)
                    let delta_start = get_offset(self.file)?;

                    // Step 4: Apply the delta to the base object
                    let object = apply_delta(self.file, &base_object)?;

                    // Step 5: Seek back to delta_start (in case zlib decoder read extra bytes)
                    seek(self.file, delta_start)?;

                    // Step 6: Read the zlib stream (to ensure the size is correct)
                    read_zlib_stream(self.file, size)?;

                    // Return the object created from applying the delta
                    object
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported object type"));
                }
            };

            read_objects.insert(offset, git_object.clone());
            
            // Step 4: Write the object to the .git/objects directory
            git_object.write()?;
        }

        Ok(commits)
    }

}

