use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::{fmt, fs};
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::str::FromStr;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};

const HASH_BYTES: usize = 20;
const COMMIT_OBJECT_TYPE: &[u8] = b"commit";
const TREE_OBJECT_TYPE: &[u8] = b"tree";
const BLOB_OBJECT_TYPE: &[u8] = b"blob";
const TAG_OBJECT_TYPE: &[u8] = b"tag";

fn make_error(message: &str) -> Error {
    Error::new(ErrorKind::Other, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hash([u8; HASH_BYTES]);

impl FromStr for Hash {
    type Err = Error;

    fn from_str(hex_hash: &str) -> io::Result<Self> {
        hex_to_hash(hex_hash.as_bytes()).ok_or_else(|| make_error(&format!("Invalid hash: {}", hex_hash)))
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

fn hex_to_hash(hex_hash: &[u8]) -> Option<Hash> {
    let mut bytes = [0; HASH_BYTES];
    hex_hash
        .chunks(2)
        .enumerate()
        .try_for_each(|(i, chunk)| {
            let val = u8::from_str_radix(&String::from_utf8_lossy(chunk), 16).ok()?;
            bytes[i] = val;
            Some(())
        })?;
    Some(Hash(bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

#[derive(Debug)]
struct Object {
    object_type: ObjectType,
    contents: Vec<u8>,
}

impl Object {
    fn hash(&self) -> Hash {
        use sha1::digest::Update;
        let object_type_str = match self.object_type {
            ObjectType::Commit => COMMIT_OBJECT_TYPE,
            ObjectType::Tree => TREE_OBJECT_TYPE,
            ObjectType::Blob => BLOB_OBJECT_TYPE,
            ObjectType::Tag => TAG_OBJECT_TYPE,
        };
        let data = [
            object_type_str,
            b" ",
            self.contents.len().to_string().as_bytes(),
            b"\0",
            &self.contents,
        ]
        .concat();
        Hash(Sha1::new().chain(data).finalize().into())
    }
}

pub fn store_packfile(target_dir: &str, pack_data: Vec<u8>) -> io::Result<Option<Hash>> {
    let pack_dir = format!("{}/.git/objects/pack", target_dir);
    fs::create_dir_all(&pack_dir)?;

    let pack_file_path = format!("{}/packfile.pack", pack_dir);
    let mut pack_file = File::create(&pack_file_path)?;
    pack_file.write_all(&pack_data)?;

    println!("Packfile downloaded and stored at: {} (size: {} bytes)", pack_file_path, pack_data.len());

    let mut pack_file_for_reading = File::open(&pack_file_path)?;
    let git_objects_dir = format!("{}/.git/objects", target_dir);
    
    index_pack_file(&mut pack_file_for_reading, &git_objects_dir)
}

fn store_git_object(target_dir: &str, object: &Object) -> io::Result<()> {
    let object_hash = object.hash();
    let object_hash_str = format!("{}", object_hash);

    let dir_name = &object_hash_str[..2];
    let file_name = &object_hash_str[2..];
    let object_dir_path = format!("{}/{}", target_dir, dir_name);
    let object_file_path = format!("{}/{}", object_dir_path, file_name);

    fs::create_dir_all(&object_dir_path)?;

    let mut object_data = Vec::new();
    let object_type_str = match object.object_type {
        ObjectType::Commit => "commit",
        ObjectType::Tree => "tree",
        ObjectType::Blob => "blob",
        ObjectType::Tag => "tag",
    };
    let header = format!("{} {}\0", object_type_str, object.contents.len());
    object_data.extend_from_slice(header.as_bytes());
    object_data.extend_from_slice(&object.contents);

    let mut compressed_data = Vec::new();
    let mut encoder = ZlibEncoder::new(&mut compressed_data, Compression::default());
    encoder.write_all(&object_data)?;
    encoder.finish()?;

    let mut file = File::create(&object_file_path)?;
    file.write_all(&compressed_data)?;

    Ok(())
}

fn index_pack_file(file: &mut File, output_dir: &str) -> io::Result<Option<Hash>> {
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
    let mut last_commit_hash: Option<Hash> = None;
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
                let object = Object { object_type, contents };
                if object_type == Commit {
                    last_commit_hash = Some(object.hash());
                }
                object
            },
            6 => {
                let delta_offset = read_offset_encoding(file)?;
                let base_offset = offset.checked_sub(delta_offset).unwrap();
                let object = apply_delta(file, &read_objects[&base_offset])?;
                object
            },
            _ => return Err(make_error(&format!("Unexpected object type {}", object_type))),
        };

        store_git_object(output_dir, &object)?;
        read_objects.insert(offset, object);
    }

    let _pack_checksum: [u8; HASH_BYTES] = read_bytes(file)?;
    let end = at_end_of_stream(file)?;
    assert!(end);

    Ok(last_commit_hash)
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

    Ok(Object { object_type, contents: result })
}

fn apply_delta_instruction<R: Read>(stream: &mut R, base: &[u8], result: &mut Vec<u8>) -> io::Result<bool> {
    let instruction = match read_bytes(stream) {
        Ok([instruction]) => instruction,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(false),
        Err(err) => return Err(err),
    };
    if instruction & 1 << 7 == 0 {
        if instruction == 0 {
            return Err(make_error("Invalid data instruction"));
        }
        let mut data = vec![0; instruction as usize];
        stream.read_exact(&mut data)?;
        result.extend_from_slice(&data);
    } else {
        let mut nonzero_bytes = instruction;
        let offset = read_partial_int(stream, 4, &mut nonzero_bytes)?;
        let mut size = read_partial_int(stream, 3, &mut nonzero_bytes)?;
        if size == 0 {
            size = 0x10000;
        }
        let base_data = base.get(offset..(offset + size)).ok_or_else(|| make_error("Invalid copy instruction"))?;
        result.extend_from_slice(base_data);
    }
    Ok(true)
}

fn read_bytes<R: Read, const N: usize>(stream: &mut R) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
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

fn at_end_of_stream<R: Read>(stream: &mut R) -> io::Result<bool> {
    Ok(stream.read(&mut [0])? == 0)
}

fn read_u32<R: Read>(stream: &mut R) -> io::Result<u32> {
    let bytes = read_bytes(stream)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_size_encoding<R: Read>(stream: &mut R) -> io::Result<usize> {
    let mut value = 0;
    let mut length = 0;
    loop {
        let (byte_value, more_bytes) = read_varint_byte(stream)?;
        value |= (byte_value as usize) << length;
        if !more_bytes {
            return Ok(value);
        }
        length += 7;
    }
}

fn read_varint_byte<R: Read>(stream: &mut R) -> io::Result<(u8, bool)> {
    let [byte] = read_bytes(stream)?;
    let value = byte & !(1 << 7);
    let more_bytes = byte & (1 << 7) != 0;
    Ok((value, more_bytes))
}

fn read_type_and_size<R: Read>(stream: &mut R) -> io::Result<(u8, usize)> {
    let value = read_size_encoding(stream)?;
    let object_type = (value >> 4) as u8;
    let size = value & 0xF;
    Ok((object_type, size))
}

fn read_partial_int<R: Read>(stream: &mut R, bytes: u8, present_bytes: &mut u8) -> io::Result<usize> {
    let mut value = 0;
    for i in 0..bytes {
        if *present_bytes & 1 != 0 {
            let [byte] = read_bytes(stream)?;
            value |= (byte as usize) << (i * 8);
        }
        *present_bytes >>= 1;
    }
    Ok(value)
}

fn read_offset_encoding<R: Read>(stream: &mut R) -> io::Result<u64> {
    let mut value = 0;
    loop {
        let (byte_value, more_bytes) = read_varint_byte(stream)?;
        value = (value << 7) | byte_value as u64;
        if !more_bytes {
            return Ok(value);
        }
        value += 1;
    }
}

fn seek(file: &mut File, offset: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    Ok(())
}

fn get_offset(file: &mut File) -> io::Result<u64> {
    file.seek(SeekFrom::Current(0))
}
