#[cfg(feature = "derive")]

use der::{Sequence, ValueOrd};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
struct Point {
    pub x: i8,
    pub y: i8,
}

#[test]
fn test_parse_der() {
    let bytes_der = &[0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43];
    let _: Point = der::Decode::from_der(bytes_der.as_slice()).unwrap();
}

#[test]
fn test_parse_ber() {
    let bytes_ber = &[0x30, 0x80, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43, 0x00, 0x00];
    let point: Point = der::Decode::from_ber(bytes_ber.as_slice()).unwrap();
    println!("x: {}, y: {}", point.x, point.y);
}
