//! Reader trait.

pub(crate) mod nested;
#[cfg(feature = "pem")]
pub(crate) mod pem;
pub(crate) mod slice;

pub(crate) use nested::NestedReader;

use crate::{
    asn1::ContextSpecific, Decode, DecodeValue, Encode, Error, ErrorKind, FixedTag, Header, Length,
    Result, Tag, TagMode, TagNumber,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use std::ops::Sub;

// Used for reading indefinite length data
/// Length of end-of-content (eoc) markers
const EOC_LENGTH: Length = Length::new(2);
/// end-of-content (eoc) marker
const EOC_MARKER: &[u8; 2] = &[0u8; 2];
/// Recursive calls limit for parsing indefinite length values (BER)
const INDEFINITE_LENGTH_PARSER_RECURSION_MAX: u16 = 1024;

/// Reader trait which reads DER-encoded input.
pub trait Reader<'r>: Sized {
    /// Get the length of the input.
    fn input_len(&self) -> Length;

    /// Peek at the next byte of input without modifying the cursor.
    fn peek_byte(&self) -> Option<u8>;

    /// Peek forward in the input data, attempting to decode a [`Header`] from
    /// the data at the current position in the decoder.
    ///
    /// Does not modify the decoder's state.
    fn peek_header(&self) -> Result<Header>;

    /// Peek next two bytes for an end-of-content marker.
    fn peek_eoc(&self) -> Result<bool>;

    /// Get the position within the buffer.
    fn position(&self) -> Length;

    /// Rewind cursor by a given offset (`self.position -= offset`).
    fn rewind(&mut self, offset: Length) -> Result<()>;

    /// Are we parsing BER?
    fn is_parsing_ber(&self) -> bool;

    /// Attempt to read data borrowed directly from the input as a slice,
    /// updating the internal cursor position.
    ///
    /// # Returns
    /// - `Ok(slice)` on success
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    /// - `Err(ErrorKind::Reader)` if the reader can't borrow from the input
    fn read_slice(&mut self, len: Length) -> Result<&'r [u8]>;

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field with the
    /// provided [`TagNumber`].
    fn context_specific<T>(&mut self, tag_number: TagNumber, tag_mode: TagMode) -> Result<Option<T>>
    where
        T: DecodeValue<'r> + FixedTag,
    {
        Ok(match tag_mode {
            TagMode::Explicit => ContextSpecific::<T>::decode_explicit(self, tag_number)?,
            TagMode::Implicit => ContextSpecific::<T>::decode_implicit(self, tag_number)?,
        }
        .map(|field| field.value))
    }

    /// Decode a value which impls the [`Decode`] trait.
    fn decode<T: Decode<'r>>(&mut self) -> Result<T> {
        let decoded = T::decode(self).map_err(|e| e.nested(self.position()));

        if decoded.is_ok() && self.is_parsing_ber() {
            // Eventually consume eoc octets
            self.read_eoc()?;
        }

        decoded
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    fn error(&mut self, kind: ErrorKind) -> Error {
        kind.at(self.position())
    }

    /// Finish decoding, returning the given value if there is no
    /// remaining data, or an error otherwise
    fn finish<T>(&mut self, value: T) -> Result<T> {
        if self.is_parsing_ber() {
            // Eventually consume eoc octets
            self.read_eoc()?;
        }

        if !self.is_finished() {
            Err(ErrorKind::TrailingData {
                decoded: self.position(),
                remaining: self.remaining_len(),
            }
            .at(self.position()))
        } else {
            Ok(value)
        }
    }

    /// Have we read all of the input data?
    fn is_finished(&self) -> bool {
        self.remaining_len().is_zero()
    }

    /// Offset within the original input stream.
    ///
    /// This is used for error reporting, and doesn't need to be overridden
    /// by any reader implementations (except for the built-in `NestedReader`,
    /// which consumes nested input messages)
    fn offset(&self) -> Length {
        self.position()
    }

    /// Peek at the next byte in the decoder and attempt to decode it as a
    /// [`Tag`] value.
    ///
    /// Does not modify the decoder's state.
    fn peek_tag(&self) -> Result<Tag> {
        match self.peek_byte() {
            Some(byte) => byte.try_into(),
            None => Err(Error::incomplete(self.input_len())),
        }
    }

    /// Read a single byte.
    fn read_byte(&mut self) -> Result<u8> {
        let mut buf = [0];
        self.read_into(&mut buf)?;
        Ok(buf[0])
    }

    /// Attempt to read input data, writing it into the provided buffer, and
    /// returning a slice on success.
    ///
    /// # Returns
    /// - `Ok(slice)` if there is sufficient data
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8]> {
        let input = self.read_slice(buf.len().try_into()?)?;
        buf.copy_from_slice(input);
        Ok(buf)
    }

    /// Read nested data of the given length. Reader's cursor points to the first nested object.
    fn read_nested<'n, T, F>(&'n mut self, len: Length, f: F) -> Result<T>
    where
        F: FnOnce(&mut NestedReader<'n, Self>) -> Result<T>,
    {
        let mut reader = NestedReader::new(self, len)?;
        let ret = f(&mut reader)?;
        reader.finish(ret)
    }

    /// Read a byte vector of the given length.
    #[cfg(feature = "alloc")]
    fn read_vec(&mut self, len: Length) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; usize::try_from(len)?];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Read an end-of-content value and verify it.
    /// Returns `Ok(true)`, if an eoc marker was read, `Ok(false)` if not and `Err()`, if an
    /// invalid eoc marker was detected.
    fn read_eoc(&mut self) -> Result<bool> {
        let next = self.peek_byte();
        if next == Some(0) {
            let eoc = self.read_slice(EOC_LENGTH)?;
            if eoc.ne(EOC_MARKER) {
                Err(ErrorKind::EndOfContent.at(self.position()))
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    /// Get the number of bytes still remaining in the buffer.
    fn remaining_len(&self) -> Length {
        debug_assert!(self.position() <= self.input_len());
        self.input_len().saturating_sub(self.position())
    }

    /// Read an ASN.1 `SEQUENCE`, creating a nested [`Reader`] for the body and
    /// calling the provided closure with it.
    fn sequence<'n, F, T>(&'n mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut NestedReader<'n, Self>) -> Result<T>,
    {
        let header = Header::decode(self)?;
        header.tag.assert_eq(Tag::Sequence)?;

        let length = if header.length.is_definite() {
            header.length.try_into()?
        } else {
            self.indefinite_value_length()?
        };

        self.read_nested(length, f)
    }

    /// Obtain a slice of bytes contain a complete TLV production suitable for parsing later.
    fn tlv_bytes(&mut self) -> Result<&'r [u8]> {
        let header = self.peek_header()?;
        let header_len = header.encoded_len()?;
        let value_len = if header.length.is_definite() {
            Length::try_from(header.length)?
        } else {
            self.indefinite_value_length()?.sub(EOC_LENGTH)?
        };
        self.read_slice((header_len + value_len)?)
    }

    /// Parse the value of an indefinite tlv container object (sequence, set, strings, any) and
    /// return its length including the two eoc (end-of-content) bytes. Reader's position is the
    /// first value byte. The reader's position is rewound to the start position before the method
    /// returns.
    /// Note: this method expects a terminating eoc marker and won't work for definite length
    /// objects.
    fn indefinite_value_length(&mut self) -> Result<Length> {
        let start_position = self.position();
        // TODO bk remove
        std::println!("Saved start position: {}", start_position);

        self.indefinite_value_length_parse_to_end(0)?;

        let length = self.position().saturating_sub(start_position);
        self.rewind(length)?;

        // TODO bk remove
        std::println!("Value length is {}", (length + EOC_LENGTH)?);
        Ok((length + EOC_LENGTH)?)
    }

    /// Advance cursor to the end of a tlv. This method works for definite and (nested) indefinite
    /// length values.
    fn indefinite_value_length_parse_to_end(&mut self, recursion_depth: u16) -> Result<()> {
        if recursion_depth > INDEFINITE_LENGTH_PARSER_RECURSION_MAX {
            return Err(self.error(ErrorKind::RecursionLimitExceeded));
        }
        // TODO bk remove
        std::println!("tlv_length_parse_to_end: recursion depth is {recursion_depth}");
        std::println!("tlv_length_parse_to_end: starting loop");
        loop {
            let header = self.peek_header()?;
            // TODO bk remove
            std::println!(
                "tlv_length_parse_to_end: @{:0}: {}/{}",
                self.position(),
                header.tag,
                header.length
            );

            if header.length.is_indefinite() {
                // indefinite length: value must be parsed
                let _ = Header::decode(self)?;
                self.indefinite_value_length_parse_to_end(recursion_depth + 1)?;
                if !self.read_eoc()? {
                    return Err(self.error(ErrorKind::EndOfContent));
                };
            } else {
                let _ = self.tlv_bytes()?;
            }
            if self.peek_eoc()? || self.is_finished() {
                break;
            }
        }
        // TODO bk remove
        std::println!("tlv_length_parse_to_end: closing loop");
        Ok(())
    }
}
