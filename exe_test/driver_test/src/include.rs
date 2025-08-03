
#[link(name = "krnl")]
unsafe extern "win64" {
    pub fn function(x: i64) -> i64;
}