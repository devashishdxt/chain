use std::ops::{Deref, DerefMut};

use rustls::internal::msgs::codec::{u24, Codec, Reader};
use subtle::ConstantTimeEq;

#[derive(Debug, Copy, Clone, Default, PartialOrd, Ord)]
pub struct Bytes32(pub [u8; 32]);

impl Deref for Bytes32 {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes32 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Codec for Bytes32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.0)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let bytes_vec = read_vec_u8_u8(reader)?;

        if bytes_vec.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);

        Some(Self(bytes))
    }
}

/// This implementation is constant-time.
impl PartialEq for Bytes32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// This implementation is constant-time.
impl PartialEq<[u8; 32]> for Bytes32 {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.ct_eq(other).into()
    }
}

impl Eq for Bytes32 {}

pub fn encode_option<T: Codec>(bytes: &mut Vec<u8>, t: &Option<T>) {
    match t {
        None => bytes.push(0u8),
        Some(v) => {
            bytes.push(1u8);
            v.encode(bytes);
        }
    }
}

/// option-option needed for rustls Codec
#[allow(clippy::option_option)]
pub fn decode_option<T: Codec>(r: &mut Reader) -> Option<Option<T>> {
    let present = u8::read(r)?;
    match present {
        0 => Some(None),
        1 => {
            let v = T::read(r)?;
            Some(Some(v))
        }
        _ => None,
    }
}

pub fn encode_vec_option_u32<T: Codec>(bytes: &mut Vec<u8>, items: &[Option<T>]) {
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        encode_option(&mut sub, i);
    }

    debug_assert!(sub.len() <= 0xffff_ffff);
    (sub.len() as u32).encode(bytes);
    bytes.append(&mut sub);
}

pub fn read_vec_option_u32<T: Codec>(r: &mut Reader) -> Option<Vec<Option<T>>> {
    let len = u32::read(r)? as usize;
    let mut ret: Vec<Option<T>> = Vec::with_capacity(len);

    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(decode_option(&mut sub)?);
    }

    Some(ret)
}

pub fn encode_vec_u32<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xffff_ffff);
    (sub.len() as u32).encode(bytes);
    bytes.append(&mut sub);
}

pub fn read_vec_u32<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = u32::read(r)? as usize;

    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

/// more efficient then `codec::encode_vec_u24`
#[inline]
pub fn encode_vec_u8_u24(bytes: &mut Vec<u8>, items: &[u8]) {
    debug_assert!(items.len() <= 0xff_ffff);
    u24(items.len() as u32).encode(bytes);
    bytes.extend_from_slice(items);
}

/// more efficient then `codec::encode_vec_u16`
#[inline]
pub fn encode_vec_u8_u16(bytes: &mut Vec<u8>, items: &[u8]) {
    debug_assert!(items.len() <= 0xffff);
    (items.len() as u16).encode(bytes);
    bytes.extend_from_slice(items);
}

/// more efficient then `codec::encode_vec_u8`
#[inline]
pub fn encode_vec_u8_u8(bytes: &mut Vec<u8>, items: &[u8]) {
    debug_assert!(items.len() <= 0xff);
    (items.len() as u8).encode(bytes);
    bytes.extend_from_slice(items);
}

/// more efficient then `codec::read_vec_u24`
#[inline]
pub fn read_vec_u8_u24_limited(r: &mut Reader, max_bytes: usize) -> Option<Vec<u8>> {
    let len = u24::read(r)?.0 as usize;
    if len > max_bytes {
        return None;
    }
    r.take(len).map(|slice| slice.to_vec())
}

/// more efficient then `codec::read_vec_u16`
#[inline]
pub fn read_vec_u8_u16(r: &mut Reader) -> Option<Vec<u8>> {
    let len = usize::from(u16::read(r)?);
    r.take(len).map(|slice| slice.to_vec())
}

/// more efficient then `codec::read_vec_u8`
#[inline]
pub fn read_vec_u8_u8(r: &mut Reader) -> Option<Vec<u8>> {
    let len = usize::from(u8::read(r)?);
    r.take(len).map(|slice| slice.to_vec())
}
