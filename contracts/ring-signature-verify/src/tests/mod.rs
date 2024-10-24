use crate::verify_signature;

const MESSAGE: &'static [u8] = b"hello, world!";

#[test]
fn test_signature_verify() {
    let buf = include_bytes!("./sign-rsa2l-700.bin");

    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    assert_eq!(buf.len(), 4 + 256 + 256 + n * (256 + 256 + 4));
    let c0 = &buf[4..4 + 256];
    let image = &buf[4 + 256..4 + 256 + 256];
    let mut n_buf: Vec<u8> = vec![];
    let mut e_buf: Vec<u8> = vec![];
    let mut r_buf: Vec<u8> = vec![];
    for i in 0..n {
        let start_offset = 4 + 256 + 256 + i * (256 + 256 + 4);
        r_buf.extend(&buf[start_offset..start_offset + 256]);
        let e_bytes = &buf[start_offset + 256..start_offset + 256 + 4];
        e_buf.extend(e_bytes);
        n_buf.extend(&buf[start_offset + 256 + 4..start_offset + 256 + 4 + 256]);
    }
    verify_signature(n, &MESSAGE, &n_buf, &e_buf, c0, &r_buf, &image).unwrap();
}
