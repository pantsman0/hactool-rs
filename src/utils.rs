use std::io::{Read, Seek, SeekFrom, Cursor};

use binrw::{file_ptr::IntoSeekFrom, helpers::until_eof, prelude::*, Endian, FilePtr};

#[derive(Debug, Clone, Copy)]
pub struct CurPos(pub u64);

impl BinRead for CurPos {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(reader: &mut R, _: Endian, _: Self::Args<'_>) -> BinResult<Self> {
        Ok(CurPos(reader.stream_position()?))
    }
}

pub fn until_eob<R, T, I, Arg, Ret>(bytes: I) -> impl Fn(&mut R, Endian, Arg) -> BinResult<Ret>
where
    I: AsRef<[u8]>,
    T: BinRead<Args<'static> = Arg>,
    R: Read + Seek,
    Arg: Clone,
    Ret: FromIterator<T>,
{
    move |_: &mut R, endian, args| {
        let container:Vec<u8> = bytes.as_ref().into();
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(container);
        until_eof(&mut cursor, endian, args)
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

pub(crate) fn read_restore<R: Read + Seek, T: From<Vec<u8>>>(reader: &mut R, offset: u64, byte_count:u64) -> std::io::Result<T> {
    let mut output = vec![0; byte_count as usize];

    let restore_position = reader.stream_position()?;
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(&mut output.as_mut_slice())?;
    reader.seek(SeekFrom::Start(restore_position))?;

    return Ok(output.into());
}