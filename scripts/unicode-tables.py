# Writes crates/veilway-proto/src/unicode.rs: the four facts about a character that the display filter and the direction of a text need, taken from the Unicode Character Database of one version.
# It fetches the files of that version, checks each against the SHA-256 written here, and prints the size of every table. To move to a later version of Unicode, change VERSION and the four digests, and run it again:
#   docker run --rm -v "$PWD":/w -w /w python:3 python -I scripts/unicode-tables.py crates/veilway-proto/src/unicode.rs
# With a second argument, a directory that already holds the four files, nothing is fetched.
import hashlib, os, sys, urllib.request

VERSION = "17.0.0"
FILES = {
    "Scripts.txt": "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf",
    "extracted/DerivedJoiningType.txt": "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d",
    "extracted/DerivedCombiningClass.txt": "191463abfbd202703c6fd6776a92a23ac44ec65e0476a7f95aa91ca492cef29b",
    "extracted/DerivedGeneralCategory.txt": "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e",
    "extracted/DerivedBidiClass.txt": "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
}

def load(name):
    data = open(os.path.join(sys.argv[2], name.split("/")[-1]), "rb").read() if len(sys.argv) > 2 else urllib.request.urlopen(f"https://www.unicode.org/Public/{VERSION}/ucd/{name}").read()
    if hashlib.sha256(data).hexdigest() != FILES[name]: sys.exit(f"{name} is not the file of Unicode {VERSION}")
    values = {}
    for line in data.decode().splitlines():
        fields = [field.strip() for field in line.split("#")[0].split(";")]
        if len(fields) < 2: continue
        first, _, last = fields[0].partition("..")
        for point in range(int(first, 16), int(last or first, 16) + 1): values[point] = fields[1]
    return values

script, joining, combining, category, bidi = (load(name) for name in FILES)
scripts = sorted(set(script.values()) - {"Common", "Inherited"})
# A letter with a script of its own, by the number of that script. Common and Inherited are left out: two letters of no script do not share one.
letters = {point: scripts.index(script[point]) + 1 for point, value in category.items() if value[0] == "L" and script.get(point) in scripts}
joins = {point: " TLDR".index(value) for point, value in joining.items() if value in ("T", "L", "D", "R")}
viramas = sorted(point for point, value in combining.items() if value == "9")
# Every character that is not strong left to right, which is the class of whatever the file does not list: 2 for a strong right-to-left one (R and AL), 1 for the rest.
weak = {point: 2 if value in ("R", "AL") else 1 for point, value in bidi.items() if value != "L"}

def table(name, values, about):
    rows = []
    for point in sorted(values):
        if rows and rows[-1][0] + rows[-1][1] + 1 == point and rows[-1][2] == values[point] and rows[-1][1] < 0xffff: rows[-1][1] += 1
        else: rows.append([point, 0, values[point]])
    print(name, len(rows), "ranges,", 8 * len(rows), "bytes")
    lines = "\n".join("\t" + " ".join(f"({first:#x}, {extent}, {value})," for first, extent, value in rows[at:at + 8]) for at in range(0, len(rows), 8))
    return f"// {about}\nconst {name}: [(u32, u16, u8); {len(rows)}] = [\n{lines}\n];\n"

print("VIRAMAS", len(viramas), "characters,", 4 * len(viramas), "bytes")
print("scripts", len(scripts), "joining letters outside LETTERS", sum(1 for point, value in joins.items() if value > 1 and point not in letters))
out = f"""//! Four facts about a character, from the Unicode Character Database {VERSION}: the script of a letter, how it joins, whether it is a virama, and whether it has a strong direction.
//! This file is written by `scripts/unicode-tables.py` and is never edited by hand. Every table is sorted, and a row is the first character of a range, the number of characters that follow it in the range, and the value.

/// How a character joins its neighbours in cursive writing (Joining_Type), as far as the display filter asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Joining {{
	/// Joining_Type T: a mark, which joining passes through.
	Transparent,
	Left,
	Dual,
	Right,
	/// Everything else: it does not join, or it only causes joining.
	Other,
}}

{table("LETTERS", letters, f"General_Category L with a Script other than Common and Inherited. The value is the number of the script among the {len(scripts)} of this version, in the order of their names, from 1.")}
{table("JOINING", joins, "Joining_Type T, L, D and R, as 1, 2, 3 and 4.")}
{table("WEAK", weak, "Bidi_Class other than L, which is the class of every character that is not here: 2 for R and AL, 1 for all the others.")}
// Canonical_Combining_Class 9.
const VIRAMAS: [u32; {len(viramas)}] = [{", ".join(f"{point:#x}" for point in viramas)}];

fn find(table: &[(u32, u16, u8)], c: char) -> u8 {{
	let at = table.partition_point(|row| row.0 <= c as u32);
	at.checked_sub(1).and_then(|at| table.get(at)).filter(|row| c as u32 - row.0 <= u32::from(row.1)).map_or(0, |row| row.2)
}}

/// The script of a letter, as a number that only says whether two letters share a script. `None` for what is no letter (General_Category L) and for a letter of no script of its own (Common and Inherited).
pub(crate) fn letter(c: char) -> Option<u8> {{Some(find(&LETTERS, c)).filter(|script| *script != 0)}}

pub(crate) fn joining(c: char) -> Joining {{[Joining::Other, Joining::Transparent, Joining::Left, Joining::Dual, Joining::Right][usize::from(find(&JOINING, c)).min(4)]}}

/// Whether the character has Canonical_Combining_Class 9.
pub(crate) fn virama(c: char) -> bool {{VIRAMAS.binary_search(&(c as u32)).is_ok()}}

/// `Some(true)` for a strong right-to-left character (Bidi_Class R and AL), `Some(false)` for a strong left-to-right one (L), `None` for every other.
pub(crate) fn strong(c: char) -> Option<bool> {{[Some(false), None, Some(true)][usize::from(find(&WEAK, c)).min(2)]}}
"""
open(sys.argv[1], "w").write(out)
