use der::{asn1::Any, Decode, Tagged};
#[cfg(feature = "derive")]
use der::{Sequence, ValueOrd};

// Recursive expansion of Sequence macro (thank you, `cargo expand`)
// =================================================================
// impl<'__der_lifetime> ::der::DecodeValue<'__der_lifetime> for Point {
//     fn decode_value<R: ::der::Reader<'__der_lifetime>>(
//         reader: &mut R,
//         header: ::der::Header,
//     ) -> ::der::Result<Self> {
//         use ::der::{Decode as _, DecodeValue as _, Reader as _};
//         reader.read_nested(header.length, |reader| {
//             let x = reader.decode()?;
//             let y = reader.decode()?;
//             Ok(Self { x, y })
//         })
//     }
// }
// impl<'__der_lifetime> ::der::EncodeValue for Point {
//     fn value_len(&self) -> ::der::Result<::der::Length> {
//         use ::der::Encode as _;
//         [self.x.encoded_len()?, self.y.encoded_len()?]
//             .into_iter()
//             .try_fold(::der::Length::ZERO, |acc, len| acc + len)
//     }
//     fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
//         use ::der::Encode as _;
//         self.x.encode(writer)?;
//         self.y.encode(writer)?;
//         Ok(())
//     }
// }
// impl<'__der_lifetime> ::der::Sequence<'__der_lifetime> for Point {}
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
struct Point {
    pub x: i8,
    pub y: i8,
    name: String,
}

#[test]
fn test_parse_der() {
    let bytes_der = &[
        0x30, 0x0a, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43, 0x0c, 0x02, 0x48, 0x69,
    ];
    let _: Point = der::Decode::from_der(bytes_der.as_slice()).unwrap();
}

#[test]
fn test_parse_ber() {
    let bytes_ber = &[
        0x30, 0x80, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43, 0x0c, 0x02, 0x48, 0x69, 0x00, 0x00,
    ];
    let point: Point = der::Decode::from_ber(bytes_ber.as_slice()).unwrap();
    println!("x: {}, y: {}, name: {:?}", point.x, point.y, point.name);
}

#[test]
fn test_parse_ber_string_indefinite() {
    let bytes_ber = &[
        0x30, 0x80, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43, 0x0c, 0x80, 0x0c, 0x02, 0x48, 0x69, 0x00,
        0x00, 0x00, 0x00,
    ];
    let point: Point = der::Decode::from_ber(bytes_ber.as_slice()).unwrap();
    println!("x: {}, y: {}, name: {:?}", point.x, point.y, point.name);
}

#[test]
fn test_parse_ber_string_indefinite_and_constructed() {
    let bytes_ber = &[
        0x30, 0x80, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x32, 0x0c, 0x80, 0x0c, 0x07, 0x54, 0x69, 0x74,
        0x61, 0x6e, 0x69, 0x63, 0x0c, 0x01, 0x20, 0x0c, 0x06, 0x73, 0x6c, 0x65, 0x65, 0x70, 0x73,
        0x0c, 0x01, 0x20, 0x0c, 0x05, 0x68, 0x65, 0x72, 0x65, 0x21, 0x00, 0x00, 0x00, 0x00,
    ];
    let point: Point = der::Decode::from_ber(bytes_ber.as_slice()).unwrap();
    println!("x: {}, y: {}, name: {:?}", point.x, point.y, point.name);
}

#[test]
fn test_parse_ber_any_indefinite() {
    // Contained value has definite length
    let bytes_ber = &[
        //ANY       SEQUENCE    INTEGER           SET         EOC
        0xa0, 0x80, 0x30, 0x05, 0x02, 0x01, 0x01, 0x31, 0x00, 0x00, 0x00,
    ];
    let any = Any::from_ber(bytes_ber.as_slice()).unwrap();
    println!("ANY: Tag: {}, Value: {:02x?}", any.tag(), any.value());

    // Contained value has indefinite length
    // This is a real world example from EJBCA
    let bytes_ber = &[
        //ANY       SEQUENCE    INTEGER           SET         EOC         EOC
        0xa0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let any = Any::from_ber(bytes_ber.as_slice()).unwrap();
    println!("ANY: Tag: {}, Value: {:02x?}", any.tag(), any.value());

    #[rustfmt::skip]
    let bytes_ber = &[
        0xa0, 0x80, // ANY (indefinite length)
          0x30, 0x80, // SEQUENCE (indefinite length)
            0x02, 0x01, 0x01, // INTEGER
            0x31, 0x00, // SET
            0xa0, 0x80, // ANY  (indefinite length)
              0x30, 0x0b, // SET (definite length)
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, // OBJECT IDENTIFIER
            0x00, 0x00, // EOC
          0x00, 0x00, // EOC
        0x00, 0x00, // EOC
    ];
    let any = Any::from_ber(bytes_ber.as_slice()).unwrap();
    println!("ANY: Tag: {}, Value: {:02x?}", any.tag(), any.value());
}
