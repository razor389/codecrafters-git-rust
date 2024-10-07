use std::io;

pub struct GitObjectHeader {
    pub object_type: String,
    pub size: usize,
}

impl GitObjectHeader {
    /// Parse a header from raw data.
    pub fn from_bytes(data: &[u8]) -> io::Result<(GitObjectHeader, &[u8])> {
        // Find the null byte (\0) that separates the header from the object data
        if let Some(pos) = data.iter().position(|&b| b == 0) {
            let header_str = std::str::from_utf8(&data[..pos])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid header"))?;

            // Split the header into type and size
            let mut parts = header_str.split_whitespace();
            let object_type = parts.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing object type in header")
            })?.to_string();

            let size = parts.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing size in header")
            })?.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid size in header")
            })?;

            let header = GitObjectHeader { object_type, size };

            // Return the parsed header and the remaining data after the null byte
            Ok((header, &data[pos + 1..]))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Header not found"))
        }
    }
}

