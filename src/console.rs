pub(crate) struct Console{
    pub(crate) currentLine: isize,
    pub(crate) currentCharSize: isize,
    pub(crate) vga_width: isize,
    pub(crate) vga_height: isize,
    pub(crate) cursor_pose: isize,
    pub(crate) vga_buffer: *mut u8
}
fn numToStr(){

}
impl Console{
    pub(crate) fn print(&mut self, str: &[u8]){
        let mut i = 0;
        while (i < str.len()) {
            if (self.cursor_pose % 2 != 0){
                //cursor pose must be even if it isn't add 1 to correct it and break because something must have gone wrong
                self.cursor_pose += 1;
                break;
            }

            if (str[i] == b'\n') {
                self.cursor_pose += (self.vga_width *  2) - (self.currentCharSize * 2);
                self.currentLine += 1;
                self.currentCharSize = 0;
            } else {
                unsafe {
                    //overwrite protection
                    if (self.vga_buffer.offset(self.cursor_pose) > 0xB8FA0 as *mut u8) {
                        break;
                    }
                    *self.vga_buffer.offset(self.cursor_pose) = str[i];
                    *self.vga_buffer.offset(self.cursor_pose + 1) = 0x07;

                }
                self.cursor_pose += 2;
                //keep track of the amount of chars on the current line
                self.currentCharSize +=1;
            }
            i += 1;
        }
    }
}
