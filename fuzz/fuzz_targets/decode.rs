#![no_main]
use cryptid_rs::Codec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codec = Codec::new("test", b"random-key");
    let _ = codec.decode(&String::from_utf8_lossy(data));
});
