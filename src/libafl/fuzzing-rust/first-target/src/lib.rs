use std::{
    alloc::{alloc, Layout},
    str::from_utf8_unchecked,
};

const DEFAULT_BUFFER_SIZE: usize = 128;

#[no_mangle]
pub fn decode(mut encoded_input: &[u8]) -> Vec<u8> {
    let decoded_len = DEFAULT_BUFFER_SIZE + encoded_input.len()
        - (encoded_input.iter().filter(|c| **c == b'%').count() * 2);

    if decoded_len <= 0 {
        return Vec::new();
    }

    let decoded_layout = Layout::array::<u8>(decoded_len).expect("Could not create layout");

    let decoded = unsafe { alloc(decoded_layout) };
    let mut decoded_ptr = decoded;

    loop {
        let mut parts = encoded_input.splitn(2, |&c| c == b'%');
        let not_escaped_part = parts.next().expect("Did not get any unescaped data");
        let rest = parts.next();

        if rest.is_none() && decoded == decoded_ptr {
            return encoded_input.to_vec();
        } else {
            for not_escaped_byte in not_escaped_part {
                unsafe { *decoded_ptr = *not_escaped_byte };
                unsafe { decoded_ptr = decoded_ptr.add(1) };
            }
            if let Some(rest) = rest {
                if let Some(&[first, second]) = rest.get(0..2) {
                    if let Ok(first_val) =
                        u8::from_str_radix(unsafe { from_utf8_unchecked(&[first]) }, 16)
                    {
                        if let Ok(second_val) =
                            u8::from_str_radix(unsafe { from_utf8_unchecked(&[second]) }, 16)
                        {
                            unsafe { *decoded_ptr = (first_val << 4) | second_val };
                            unsafe { decoded_ptr = decoded_ptr.add(1) };
                            encoded_input = &rest[2..];
                        } else {
                            unsafe { *decoded_ptr = b'%' };
                            unsafe { decoded_ptr = decoded_ptr.add(1) };
                            unsafe { *decoded_ptr = first };
                            unsafe { decoded_ptr = decoded_ptr.add(1) };
                            encoded_input = &rest[1..];
                        }
                    } else {
                        unsafe { *decoded_ptr = b'%' };
                        unsafe { decoded_ptr = decoded_ptr.add(1) };
                        encoded_input = rest;
                    }
                } else {
                    unsafe { *decoded_ptr = b'%' };
                    unsafe { decoded_ptr = decoded_ptr.add(1) };

                    for rest_byte in rest {
                        unsafe { *decoded_ptr = *rest_byte };
                        unsafe { decoded_ptr = decoded_ptr.add(1) };
                    }

                    break;
                }
            } else {
                break;
            }
        }
    }

    unsafe { Vec::from_raw_parts(decoded, decoded_len, decoded_len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_decodes_successfully_emoji() {
        let expected = String::from("👾 Exterminate!").as_bytes().to_vec();
        let encoded = "%F0%9F%91%BE%20Exterminate%21".as_bytes();
        assert_eq!(expected, decode(encoded));
    }

    #[test]
    fn it_decodes_misc() {
        assert_eq!("".as_bytes().to_vec(), decode("".as_bytes()));
        assert_eq!(
            "pureascii".as_bytes().to_vec(),
            decode("pureascii".as_bytes())
        );
        assert_eq!("\0".as_bytes().to_vec(), decode("\0".as_bytes()));
        assert_eq!(
            "this that".as_bytes().to_vec(),
            decode("this%20that".as_bytes())
        );
    }

    #[test]
    fn it_crashes() {
        println!("{:?}", decode("aaaaaaaaaaaaaaaa%%%%%%%%%%%%".as_bytes()));
    }
}
