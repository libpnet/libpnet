#[test]
fn compile_test() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/*.rs");
    t.pass("tests/run-pass/*.rs");
}

#[test]
fn test_vec_primitive() {
    use pnet_macros::packet;
    use pnet_macros_support::types::u32be;

    #[packet]
    pub struct Test {
        #[length = "4"]
        pub v: Vec<u32be>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    let res = TestPacket::new(&[0x00, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(res.get_v(), vec![0]);
}
