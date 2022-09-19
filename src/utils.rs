use std::io::{Read, Seek, SeekFrom};

use binread::{BinRead, ReadOptions, BinResult};

#[derive(Debug)]
pub struct CurPos(pub u64);

impl BinRead for CurPos {
    type Args = ();

    fn read_options<R: Read + Seek>(reader: &mut R, ro: &ReadOptions, args: Self::Args) -> BinResult<Self> {
        Ok(CurPos(reader.seek(SeekFrom::Current(0))?))
    }
}