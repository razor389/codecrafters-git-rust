use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::{fmt, fs};
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::str::FromStr;
use flate2::read::ZlibDecoder;

use sha1::{Digest, Sha1};

const HASH_BYTES: usize = 20;
const COMMIT_OBJECT_TYPE: &[u8] = b"commit";
const TREE_OBJECT_TYPE: &[u8] = b"tree";
const BLOB_OBJECT_TYPE: &[u8] = b"blob";
const TAG_OBJECT_TYPE: &[u8] = b"tag";
const INDEX_FILE_SUFFIX: &str = ".idx";
const PACK_FILE_SUFFIX: &str = ".pack";
const LONG_OFFSET_FLAG: u32 = 1 << 31;
const TYPE_BITS: u8 = 3;
const VARINT_ENCODING_BITS: u8 = 7;
const TYPE_BYTE_SIZE_BITS: u8 = VARINT_ENCODING_BITS - TYPE_BITS;
const VARINT_CONTINUE_FLAG: u8 = 1 << VARINT_ENCODING_BITS;
const COPY_INSTRUCTION_FLAG: u8 = 1 << 7;
const COPY_OFFSET_BYTES: u8 = 4;
const COPY_SIZE_BYTES: u8 = 3;
const COPY_ZERO_SIZE: usize = 0x10000;

fn make_error(message: &str) -> Error {
    Error::new(ErrorKind::Other, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hash([u8; HASH_BYTES]);

fn hex_char_value(hex_char: u8) -> Option<u8> {
  match hex_char {
    b'0'..=b'9' => Some(hex_char - b'0'),
    b'a'..=b'f' => Some(hex_char - b'a' + 10),
    _ => None,
  }
}

fn hex_to_hash(hex_hash: &[u8]) -> Option<Hash> {
  const BITS_PER_CHAR: usize = 4;
  const CHARS_PER_BYTE: usize = 8 / BITS_PER_CHAR;

  let byte_chunks = hex_hash.chunks_exact(CHARS_PER_BYTE);
  if !byte_chunks.remainder().is_empty() {
    return None
  }

  let bytes = byte_chunks.map(|hex_digits| {
    hex_digits.iter().try_fold(0, |value, &byte| {
      let char_value = hex_char_value(byte)?;
      Some(value << BITS_PER_CHAR | char_value)
    })
  }).collect::<Option<Vec<_>>>()?;
  let bytes = <[u8; HASH_BYTES]>::try_from(bytes).ok()?;
  Some(Hash(bytes))
}

impl FromStr for Hash {
  type Err = Error;

  fn from_str(hex_hash: &str) -> io::Result<Self> {
    hex_to_hash(hex_hash.as_bytes()).ok_or_else(|| {
      make_error(&format!("Invalid hash: {}", hex_hash))
    })
  }
}

impl Display for Hash {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    for byte in self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}


#[derive(Clone, Copy, Debug)]
enum ObjectType {
  Commit,
  Tree,
  Blob,
  Tag,
}

enum PackObjectType {
  Base(ObjectType),
  OffsetDelta,
  HashDelta,
}

#[derive(Debug)]
struct Object {
  object_type: ObjectType,
  contents: Vec<u8>,
}

impl Object {
    fn hash(&self) -> Hash {
        use sha1::digest::Update;
        use ObjectType::*;

        let hash = Sha1::new()
        .chain(match self.object_type {
            Commit => COMMIT_OBJECT_TYPE,
            Tree => TREE_OBJECT_TYPE,
            Blob => BLOB_OBJECT_TYPE,
            Tag => TAG_OBJECT_TYPE,
        })
        .chain(b" ")
        .chain(self.contents.len().to_string())
        .chain(b"\0")
        .chain(&self.contents)
        .finalize();
        Hash(<[u8; HASH_BYTES]>::try_from(hash.as_slice()).unwrap())
    }
}

fn at_end_of_stream<R: Read>(stream: &mut R) -> io::Result<bool> {
    // Try to read a byte and check whether there was one to read
    let bytes_read = stream.read(&mut [0])?;
    Ok(bytes_read == 0)
}

fn keep_bits(value: usize, bits: u8) -> usize {
    value & ((1 << bits) - 1)
}

fn read_bytes<R: Read, const N: usize>(stream: &mut R) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_u32<R: Read>(stream: &mut R) -> io::Result<u32> {
    let bytes = read_bytes(stream)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_hash<R: Read>(stream: &mut R) -> io::Result<Hash> {
    let bytes = read_bytes(stream)?;
    Ok(Hash(bytes))
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

fn read_varint_byte<R: Read>(stream: &mut R) -> io::Result<(u8, bool)> {
    let [byte] = read_bytes(stream)?;
    let value = byte & !VARINT_CONTINUE_FLAG;
    let more_bytes = byte & VARINT_CONTINUE_FLAG != 0;
    Ok((value, more_bytes))
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
  
  
// Store the downloaded packfile and index it manually
pub fn store_packfile(target_dir: &str, pack_data: Vec<u8>) -> io::Result<()> {
    let pack_dir = format!("{}/.git/objects/pack", target_dir);
    fs::create_dir_all(&pack_dir)?;

    // Step 1: Write the packfile to disk
    let pack_file_path = format!("{}/packfile.pack", pack_dir);
    let mut pack_file = fs::File::create(&pack_file_path)?;
    pack_file.write_all(&pack_data)?;

    // Debug: Log the size of the downloaded packfile
    println!("Packfile downloaded and stored at: {} (size: {} bytes)", pack_file_path, pack_data.len());

    // Step 2: Validate and index the packfile
    println!("Starting packfile validation...");
    // Open the file again for reading (using the same path)
    let mut pack_file_for_reading = File::open(&pack_file_path)?;

    
    index_pack_file(&mut pack_file_for_reading, &pack_dir)?;
    Ok(())
}

fn index_pack_file(file: &mut File, output_dir: &str) -> io::Result<()> {
    use ObjectType::*;

    let magic = read_bytes(file)?;
    if magic != *b"PACK" {
        return Err(make_error("Invalid packfile header"));
    }

    let version = read_u32(file)?;
    if version != 2 {
        return Err(make_error("Unsupported packfile version"));
    }

    let total_objects = read_u32(file)?;

    // Map from offsets to the objects that were read
    let mut read_objects = HashMap::new();
    for _ in 0..total_objects {
        let offset = get_offset(file)?;
        let (object_type, size) = read_type_and_size(file)?;
        let object = match object_type {
            1..=4 => {
                let object_type = match object_type {
                    1 => Commit,
                    2 => Tree,
                    3 => Blob,
                    _ => Tag,
                };
                let contents = read_zlib_stream(file, size)?;
                Object { object_type, contents }
            },
            6 => {
                let delta_offset = read_offset_encoding(file)?;
                let base_offset = offset.checked_sub(delta_offset).unwrap();
                let delta_start = get_offset(file)?;
                let object = apply_delta(file, &read_objects[&base_offset])?;
                seek(file, delta_start)?;
                read_zlib_stream(file, size)?;
                object
            },
            _ => return Err(make_error(&format!("Unexpected object type {}", object_type))),
        };
        read_objects.insert(offset, object);
    }

    let _pack_checksum: [u8; HASH_BYTES] = read_bytes(file)?;

    // Write index
    write_packfile_index(read_objects, output_dir)?;

        // We should be at the end of the pack file
    let end = at_end_of_stream(file)?;
    assert!(end);

    Ok(())
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

fn apply_delta(pack_file: &mut File, base: &Object) -> io::Result<Object> {
    let Object { object_type, contents: ref base } = *base;
    let mut delta = ZlibDecoder::new(pack_file);
    let base_size = read_size_encoding(&mut delta)?;
    if base.len() != base_size {
        return Err(make_error("Incorrect base object length"))
    }

    let result_size = read_size_encoding(&mut delta)?;
    let mut result = Vec::with_capacity(result_size);
    while apply_delta_instruction(&mut delta, base, &mut result)? {}
    if result.len() != result_size {
        return Err(make_error("Incorrect object length"))
    }

    // The object type is the same as the base object
    Ok(Object { object_type, contents: result })
}
  
fn apply_delta_instruction<R: Read>(stream: &mut R, base: &[u8], result: &mut Vec<u8>) -> io::Result<bool> {
    // Check if the stream has ended, meaning the new object is done
    let instruction = match read_bytes(stream) {
        Ok([instruction]) => instruction,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(false),
        Err(err) => return Err(err),
    };
    if instruction & COPY_INSTRUCTION_FLAG == 0 {
        // Data instruction; the instruction byte specifies the number of data bytes
        if instruction == 0 {
        // Appending 0 bytes doesn't make sense, so git disallows it
            return Err(make_error("Invalid data instruction"))
        }

        // Append the provided bytes
        let mut data = vec![0; instruction as usize];
        stream.read_exact(&mut data)?;
        result.extend_from_slice(&data);
    }
    else {
        // Copy instruction
        let mut nonzero_bytes = instruction;
        let offset =
        read_partial_int(stream, COPY_OFFSET_BYTES, &mut nonzero_bytes)?;
        let mut size =
        read_partial_int(stream, COPY_SIZE_BYTES, &mut nonzero_bytes)?;
        if size == 0 {
            // Copying 0 bytes doesn't make sense, so git assumes a different size
            size = COPY_ZERO_SIZE;
        }
        // Copy bytes from the base object
        let base_data = base.get(offset..(offset + size)).ok_or_else(|| {
            make_error("Invalid copy instruction")
        })?;
        result.extend_from_slice(base_data);
    }
    Ok(true)
}


// Write the packfile index (.idx)
fn write_packfile_index(objects: HashMap<u64, Object>, output_dir: &str) -> io::Result<()> {
    let idx_file_path = format!("{}/packfile.idx", output_dir);
    let mut idx_file = fs::File::create(&idx_file_path)?;

    // Write the index header (magic number + version)
    idx_file.write_all(&[0xff, 0x74, 0x4f, 0x63])?; // Magic number
    idx_file.write_all(&[0, 0, 0, 2])?; // Version number

    let mut fanout = [0u32; 256];
    let mut sha1_list = Vec::new();
    let mut offsets = Vec::new();

    // For each object, compute SHA-1 hash and determine its offset
    for (&offset, object) in objects.iter() {
        let sha1 = object.hash().0.to_vec();
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
