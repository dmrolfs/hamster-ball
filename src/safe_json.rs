// ABOUTME: Pretty JSON for any Serialize value, with a formatter that escapes bidi and control characters.
// ABOUTME: serde_json writes bidi and zero-width characters raw; this formatter turns them into \uXXXX so output cannot reorder text.
//! Terminal-safe JSON, shared by `hb explain` and `hb doctor`.
//!
//! Field order is the declaration order of the serialized structs, so the output is stable.
//! `serde_json` escapes quotes, backslashes and `U+0000`..`U+001F`, and writes
//! everything else raw, including right-to-left overrides and zero-width characters. The
//! formatter here escapes every character [`needs_escaping`] flags as `\uXXXX`, which is lossless
//! and valid JSON.

use std::io;

use serde_json::ser::{CharEscape, Formatter, PrettyFormatter, Serializer};

use crate::text::needs_escaping;

/// Pretty-prints like [`PrettyFormatter`], and escapes characters that can reorder or hide text.
struct SafeFormatter {
    pretty: PrettyFormatter<'static>,
}

impl SafeFormatter {
    fn new() -> Self {
        Self {
            pretty: PrettyFormatter::new(),
        }
    }
}

impl Formatter for SafeFormatter {
    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_array(writer)
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array(writer)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array_value(writer)
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object(writer)
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object(writer)
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_object_key(writer, first)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object_value(writer)
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (at, c) in fragment.char_indices() {
            if needs_escaping(c) {
                writer.write_all(&fragment.as_bytes()[start..at])?;
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
                start = at + c.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        char_escape: CharEscape,
    ) -> io::Result<()> {
        self.pretty.write_char_escape(writer, char_escape)
    }
}

/// Renders `value` as pretty JSON ending in a newline.
///
/// # Errors
/// [`serde_json::Error`] if serialization fails.
pub(crate) fn to_safe_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut bytes = Vec::new();
    {
        let mut serializer = Serializer::with_formatter(&mut bytes, SafeFormatter::new());
        value.serialize(&mut serializer)?;
    }
    bytes.push(b'\n');
    // The formatter only ever writes UTF-8: valid fragments and ASCII escapes.
    String::from_utf8(bytes)
        .map_err(|error| <serde_json::Error as serde::ser::Error>::custom(error.to_string()))
}
