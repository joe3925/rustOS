use crate::console;
pub(crate) extern "C" fn keyboard_interrupt_handler() {
    let mut console = console::Console{
        currentCharSize: 0,
        vga_width: 80,
        vga_height: 25,
        vga_buffer: 0xB8000 as *mut u8,
        currentLine: 0,
        cursor_pose: 0
    };

    console.print("test \n".as_ref());
}