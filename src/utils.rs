use std::io::{Read, Seek, SeekFrom, Cursor};

use binrw::{BinRead, ReadOptions, BinResult, helpers::until_eof, file_ptr::IntoSeekFrom, FilePtr};

#[derive(Debug)]
pub struct CurPos(pub u64);

impl BinRead for CurPos {
    type Args = ();

    fn read_options<R: Read + Seek>(reader: &mut R, _: &ReadOptions, _: Self::Args) -> BinResult<Self> {
        Ok(CurPos(reader.stream_position()?))
    }
}

pub fn until_eob<R, T, I, Arg, Ret>(bytes: I) -> impl Fn(&mut R, &ReadOptions, Arg) -> BinResult<Ret>
where
    I: AsRef<[u8]>,
    T: BinRead<Args = Arg>,
    R: Read + Seek,
    Arg: Clone,
    Ret: FromIterator<T>,
{
    move |_: &mut R, ro, args| {
        let container:Vec<u8> = bytes.as_ref().into();
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(container);
        until_eof(&mut cursor, ro, args)
    }
}


#[derive(BinRead, Clone, Copy, Debug)]
pub(crate) struct DummySeekFrom;
impl IntoSeekFrom for DummySeekFrom {
    fn into_seek_from(self) -> SeekFrom {
        SeekFrom::Current(0)
    }
}

pub(crate)type Placement<T> = FilePtr<DummySeekFrom, T>;