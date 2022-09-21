use std::io::{Read, Seek, SeekFrom};

use binrw::{BinRead, BinReaderExt, ReadOptions, BinResult};

#[derive(Debug)]
pub struct CurPos(pub u64);

impl BinRead for CurPos {
    type Args = ();

    fn read_options<R: Read + Seek>(reader: &mut R, ro: &ReadOptions, args: Self::Args) -> BinResult<Self> {
        Ok(CurPos(reader.seek(SeekFrom::Current(0))?))
    }
}

pub fn total_len<R, T, Arg>(bytes: usize) -> impl Fn(&mut R, &ReadOptions, Arg) -> BinResult<Vec<T>>
where
    T: BinRead<Args = Arg>,
    R: Read + Seek,
    Arg: Clone,
{
    move |reader, ro, args| {
    let start_pos = reader.seek(SeekFrom::Current(0))?;
    let mut collection:Vec<T> = vec![];
    while reader.seek(SeekFrom::Current(0))? < start_pos + bytes as u64 {
        collection.push(reader.read_type_args(ro.endian(), args.clone())?);
    }
    return Ok(collection);  
}
}