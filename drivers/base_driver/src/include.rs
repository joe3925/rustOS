#[link(name = "KRNL")]
#[unsafe(no_mangle)]
unsafe extern "win64" {
    pub fn function(x: i64) -> i64;
}
