const TNT_BUFFER_CAPACITY: usize = 0x256;

pub struct TntBuffer {
    buf: [u8; TNT_BUFFER_CAPACITY],
    cur: usize,
    end: usize,
}

impl Default for TntBuffer {
    fn default() -> Self {
        Self {
            buf: [0; TNT_BUFFER_CAPACITY],
            cur: 0,
            end: 0,
        }
    }
}

impl TntBuffer {
    pub fn new() -> Self {
        Self::default()
    }
}
