#[link(name = "KRNL")]
unsafe extern "win64" {
    pub fn function(x: i64) -> i64;
}
