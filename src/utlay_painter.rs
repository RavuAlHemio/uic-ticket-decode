//! Definition-to-text functions for U_TLAY records.


use std::fmt;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Record {
    pub line: usize,
    pub column: usize,
    pub width: usize,
    pub height: usize,
    pub text: String,
}


#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Canvas {
    canvas: Vec<Vec<char>>,
}
impl Canvas {
    pub fn new() -> Self { Self::default() }

    pub fn height(&self) -> usize {
        self.canvas.len()
    }

    pub fn width(&self) -> usize {
        self.canvas.iter()
            .map(|line| line.len())
            .max()
            .unwrap_or(0)
    }

    pub fn paint_record(&mut self, record: &Record) {
        for (i, line) in record.text.split('\n').enumerate() {
            let line_index = record.line + i;
            while line_index >= self.canvas.len() {
                self.canvas.push(Vec::new());
            }
            let canvas_line = &mut self.canvas[line_index];

            let mut column_index = record.column;
            for c in line.chars() {
                while column_index >= canvas_line.len() {
                    canvas_line.push(' ');
                }
                canvas_line[column_index] = c;
                column_index += 1;
            }
        }
    }

    pub fn as_vec(&self) -> &Vec<Vec<char>> { &self.canvas }
}
impl fmt::Display for Canvas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for row in &self.canvas {
            for c in row {
                write!(f, "{}", c)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}


fn row_to_letter(row: usize) -> char {
    const A: u32 = 'A' as u32;
    if row > 26 {
        return ' ';
    }
    let row_u32: u32 = row.try_into().unwrap();
    char::from_u32(A + row_u32).unwrap()
}


pub(crate) struct CanvasInABox<'a>(pub &'a Canvas);
impl<'a> fmt::Display for CanvasInABox<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "  ")?;
        for i in 1..self.0.width()+1 {
            let tens = (i / 10) % 10;
            write!(f, "{}", tens)?;
        }
        writeln!(f)?;

        write!(f, "  ")?;
        for i in 1..self.0.width()+1 {
            let ones = i % 10;
            write!(f, "{}", ones)?;
        }
        writeln!(f)?;

        write!(f, " \u{250C}")?;
        for _ in 0..self.0.width() {
            write!(f, "\u{2500}")?;
        }
        writeln!(f, "\u{2510}")?;

        for (i, row) in self.0.as_vec().iter().enumerate() {
            write!(f, "{}\u{2502}", row_to_letter(i))?;
            for c in row {
                write!(f, "{}", c)?;
            }
            // pad on the right
            for _ in row.len()..self.0.width() {
                write!(f, " ")?;
            }
            writeln!(f, "\u{2502}")?;
        }

        write!(f, " \u{2514}")?;
        for _ in 0..self.0.width() {
            write!(f, "\u{2500}")?;
        }
        writeln!(f, "\u{2518}")
    }
}
