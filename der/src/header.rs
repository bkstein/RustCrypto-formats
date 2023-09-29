//! ASN.1 DER headers.

use crate::{
    Decode, DerOrd, Encode, ErrorKind, IndefiniteLength, Length, Reader, Result, Tag, Writer,
};
use core::cmp::Ordering;

/// ASN.1 DER headers: tag + length component of TLV-encoded values
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Tag representing the type of the encoded value
    pub tag: Tag,

    /// Length of the encoded value
    pub length: IndefiniteLength,
}

impl Header {
    /// Create a new [`Header`] from a [`Tag`] and a specified length.
    ///
    /// Returns an error if the length exceeds the limits of [`Length`].
    pub fn new(tag: Tag, length: impl TryInto<Length>) -> Result<Self> {
        let length = length.try_into().map_err(|_| ErrorKind::Overflow)?;
        Ok(Self {
            tag,
            length: IndefiniteLength::new(length),
        })
    }
}

impl<'a> Decode<'a> for Header {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Header> {
        let tag = Tag::decode(reader)?;

        let length = IndefiniteLength::decode(reader).map_err(|e| {
            if e.kind() == ErrorKind::Overlength {
                ErrorKind::Length { tag }.into()
            } else {
                e
            }
        })?;

        Ok(Self { tag, length })
    }
}

impl Encode for Header {
    fn encoded_len(&self) -> Result<Length> {
        self.tag.encoded_len()? + self.length.encoded_len()?
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.tag.encode(writer)?;
        self.length.encode(writer)
    }
}

impl DerOrd for Header {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        match self.tag.der_cmp(&other.tag)? {
            Ordering::Equal => {
                Length::try_from(self.length)?.der_cmp(&Length::try_from(&other.length)?)
            }
            ordering => Ok(ordering),
        }
    }
}
