use std::io;

const DEFAULT_PREFIX: &str = "@cee:";
const DEFAULT_CAPACITY: usize = 10;

pub struct LumberjackWriter {
    buf_size: usize,
    cur_line: usize,
    buffer: Vec<Vec<u8>>,
    prefix: String,
    wrapped: Box<dyn io::Write>,
}

enum AppendResult {
    Done(usize),
    Continue(usize),
}

fn init_buffer<'a>(buffer: &'a mut Vec<Vec<u8>>, buf_size: usize) {
    for _ in 0..buf_size {
        buffer.push(vec![]);
    }
}

impl LumberjackWriter {
    pub fn new(wrapped: Box<dyn io::Write>, prefix: Option<String>) -> Self {
        Self::with_capacity(wrapped, prefix, DEFAULT_CAPACITY)
    }

    pub fn with_capacity(
        wrapped: Box<dyn io::Write>,
        prefix: Option<String>,
        buf_size: usize,
    ) -> Self {
        let mut buffer = Vec::with_capacity(buf_size);
        init_buffer(&mut buffer, buf_size);
        assert_eq!(buffer.len(), buf_size);
        Self {
            buf_size,
            wrapped,
            buffer,
            prefix: prefix.unwrap_or(DEFAULT_PREFIX.to_owned()),
            cur_line: 0,
        }
    }

    fn add_to_buffer(&mut self, content: &[u8], cur_pos: usize) -> AppendResult {
        let mut counter: usize = 0;

        for c in content {
            counter += 1;
            self.buffer[self.cur_line].push(*c);

            if *c == 0x0a {
                self.cur_line += 1;

                if self.cur_line < self.buf_size {
                    return self.add_to_buffer(&content[counter..], counter + cur_pos);
                } else {
                    self.cur_line = 0;
                    return AppendResult::Continue(counter + cur_pos);
                }
            }
        }

        AppendResult::Done(counter + cur_pos)
    }

    fn write_whole_buffer(&mut self) -> Result<(), io::Error> {
        assert_eq!(self.buffer.len(), self.buf_size);
        for i in 0..self.buf_size {
            if self.buffer[i].is_empty() {
                return Ok(());
            }
            self.wrapped.write(self.prefix.as_bytes())?;
            self.wrapped.write(&self.buffer[i])?;
            self.buffer[i] = vec![];
        }
        Ok(())
    }
}

impl io::Write for LumberjackWriter {
    fn flush(&mut self) -> Result<(), io::Error> {
        self.write_whole_buffer()?;
        self.wrapped.flush()
    }

    // write must pass the given content through the inner buffer first. Once this
    // is full, a write of the wrapped writer is called with the contained data and
    // the index of the content up to which the data has been read is returned. The
    // write must continue in this way until the whole content has been scanned.
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        let mut written: usize = 0;

        loop {
            match self.add_to_buffer(content[written..].into(), 0) {
                AppendResult::Continue(partial) => {
                    self.write_whole_buffer()?;
                    written += partial;
                }
                AppendResult::Done(total) => {
                    return Ok(written + total);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::LumberjackWriter;
    use std::cell::RefCell;
    use std::io::{self, Read, Write};

    #[derive(Debug)]
    struct Buf(RefCell<Vec<u8>>);

    impl Buf {
        const fn new() -> Self {
            Self(RefCell::new(Vec::new()))
        }

        fn to_owned(&self) -> String {
            String::from(std::str::from_utf8(self.0.borrow().as_ref()).unwrap())
        }
    }

    impl Read for &Buf {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
            let size = std::cmp::min(self.0.borrow().len(), buf.len());

            for i in 0..size {
                buf[i] = self.0.borrow()[i];
            }

            Ok(size)
        }
    }

    impl Write for &Buf {
        fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
            for b in buf {
                self.0.borrow_mut().push(*b);
            }

            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    impl PartialEq<Vec<u8>> for &Buf {
        fn eq(&self, other: &Vec<u8>) -> bool {
            *self.0.borrow() == *other
        }
    }

    unsafe impl Sync for Buf {}

    #[test]
    fn test_full_write() {
        static BUF: Buf = Buf::new();

        let mut lw = LumberjackWriter::with_capacity(Box::new(&BUF), None, 3);

        let three = "{\"number\":1}\n{\"number\":2}\n{\"number\":3,\"notUnicode\":\"é\"}\n";
        let exp_three =
            "@cee:{\"number\":1}\n@cee:{\"number\":2}\n@cee:{\"number\":3,\"notUnicode\":\"é\"}\n";
        let written = lw.write(three.as_bytes()).expect("unexpected ìo error");
        assert_eq!(written, three.len());
        assert_eq!(BUF.to_owned(), exp_three);

        let two = "{\"number\":4}\n{\"number\":5}\n";
        let written2 = lw.write(two.as_bytes()).expect("unexpected io error");
        assert_eq!(written2, two.len());
        assert_eq!(BUF.to_owned(), exp_three);

        let one = "{\"number\":6}\n";
        let exp_two_and_one = "@cee:{\"number\":4}\n@cee:{\"number\":5}\n@cee:{\"number\":6}\n";
        let mut exp_six = exp_three.to_owned();
        exp_six.push_str(exp_two_and_one);
        let written3 = lw.write(one.as_bytes()).expect("unexpected io error");
        assert_eq!(written3, one.len());
        assert_eq!(BUF.to_owned(), exp_six);
    }

    #[test]
    fn test_flush() {
        static BUF: Buf = Buf::new();

        let mut lw = LumberjackWriter::with_capacity(Box::new(&BUF), None, 3);

        let two = "{\"number\":4}\n{\"number\":5}\n";
        let exp_two = "@cee:{\"number\":4}\n@cee:{\"number\":5}\n";
        let written2 = lw.write(two.as_bytes()).expect("unexpected io error");
        lw.flush().expect("failed to flush");

        assert_eq!(written2, two.len());
        assert_eq!(BUF.to_owned(), exp_two);
    }
}
