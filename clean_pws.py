#!/usr/bin/env python
"""
Clean up passwords from input file and write to output file.

Updated 2026-04-11. (c) Jim Taylor. Created 2026-02-27. MIT License. Coding assistance from multiple AIs.

Autodetect if lines are in email:password or email;password format and strip
Autodetect one or more hashes/salts in front of password and strip
Autodetect if lines have password count at beginning or end of line, output at end with <tab> delimiter (or strip if args flag set)

Recognize incoming encoding (using chardet), always write in UTF-8
Remove ctrl chars and too-short and too-long passwords
Convert HTML character references and $HEX[...] sequences, including nesting
Fix character encoding errors (mojibake) with ftfy and additional heuristics
Log mojibake fixes, malformed $HEX[], and other stuff if requested
[disabled] Log suspected junk lines (mostly non-ASCII) for later examination
If Unicode replacement character (� U+FFFD) is found, skip the corrupt line
  (unlikely to be entered by a user, indicates upstream encoding issue, and can't be fixed)
Recognize hashes instead of passwords (common in .found files) and skip them

TODO: add other common hash types to HASH_PATTERNS
TODO: update junk cleaner (see other file) to remove URLs and reintegrate in this script
TODO: it looks like in many cases the password is prepended with a bit of hash stuff ($6$rounds=5000$, $6$rounds=50$)
      so could strip off and leave password (but have to avoid real passwords starting with $6$, $5$, etc.)
TODO: (maybe) Factor out into helper function(s) or always clean before count_patterns?  [Phase 1 done; Phase 2 (count_patterns) pending]

Note: Looked into option to sort, even using numpy memmap for really large files, but doesn't seem practical.
    Better to use GNU sort or similar external tool after cleaning.
"""

import argparse
import re
import time
import unicodedata
from pathlib import Path
from datetime import datetime
from html import unescape
from chardet import UniversalDetector
from ftfy import fix_encoding

   # dict to strip Unicode Cc/Cf (including ASCII ctrls and 0x7F DEL)
STRIP_CTRLS = {
  codepoint: None
  for codepoint in range(0x110000)
  if unicodedata.category(chr(codepoint)) in {"Cc", "Cf"}
} 

HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")   # for decoding \x escape sequences
HEX_MARKER_RE = re.compile(r"\$hex\[", re.IGNORECASE)   # used by decode_hex()

  # The following are used by more_mojibake(); defined here for speed outside of main loop
SUSPICIOUS_UTF8_MARKERS = "ÃÂÐÑâ"
SUSPICIOUS_UTF8_RE = re.compile(f'[{SUSPICIOUS_UTF8_MARKERS}]')
SUSPICIOUS_CYRILLIC = ("Г§", "Гѓ", "Г±", "Г©", "Г¶", "Гј", "Дџ", "Д±", "Еџ")
CYRILLIC_RE = re.compile(r'[\u0400-\u04FF]')
UTF7_MARKER = "+A"
UTF7_FIXES = {
  "+AEA-": "@",
  "+ACM-": "#",
  "+ACE-": "!",
  "+AF8-": "_",
  "+ACo-": "*",
  "+ACQ-": "$",
  "+ACY-": "&",
  "+ACU-": "%",
  "+AD0-": "=",
  "+AF4-": "^",
  "+ADs-": ";",
  "+ACI-": '"',
  "+ADw-": "<",
  "+AF0-": "]",
  "+AD4-": ">",
  "+AH0-": "}",
  "+AFs-": "[",
  "+AH4-": "~",
  "+AHs-": "{",
  "+AHw-": "|",
  "+AGA-": "`",
  "+AFw-": "\\",
}

LONG_HEX_RE = re.compile(r'^[0-9A-Fa-f]{32,}')   # used by junk_line() to detect at least 16 bytes worth of hex digits, trailing chars ok
SAMPLE_LINES = 800   # number of lines to sample for detecting email format and count delimiter
DETECT_THRESHOLD = 0.95   # if at least this fraction of sampled lines look like email:password or contain a count, consider it a match
LEN_MIN = 4   # minimum password length
LEN_MAX = 96  # maximum password length
WRITE_BUFFER_SIZE = 10_000

   # Regexes and min/max lengths for common hash formats left unfound in a .found file.
   # Lengths are slightly shorter/longer than normal to allow for some malformed variants.
   # Not doing full validation of hash, since this is often garbled/truncated data, not found passwords.
   # Used by is_hash()
HASH_PATTERNS = (
    (30,  38, re.compile(r"(?i)^\$H\$")),     # phpass
    (20,  36, re.compile(r"^\$P\$")),         # Drupal MD5
    (20,  80, re.compile(r"^\$2[aby]\$")),    # bcrypt 2 variants, including truncations
    (20,  40, re.compile(r"^\$1\$")),         # md5-crypt
    (50,  58, re.compile(r"^\$S\$")),         # Drupal 7+ sha-256
    (16,  17, re.compile(r"^\$2a\$")),        # bcrypt 2a malformed
    (46,  80, re.compile(r"^\$5\$")),         # sha256-crypt
    (16,  80, re.compile(r"^\$5\$rounds=")),  # sha256-crypt with rounds
    (90, 120, re.compile(r"^\$6\$")),         # sha512-crypt
    (16,  80, re.compile(r"^\$6\$rounds=")),  # sha512-crypt with rounds
    (36,  46, re.compile(r"^\$CP\$")),        # Coppermine Photo Gallery (?) MD5
    (24,  62, re.compile(r"^\$8[y]\$")),      # weird bcrypt 2 variant
    (60,  84, re.compile(r"^\$AES-128-CBC\$")),    # AES-128-CBC
    (9, 2048, re.compile(r"^\$argon2i(?:d)?\$")),  # argon2i/argon2id
)

def parse_args():
  parser = argparse.ArgumentParser(description="Clean passwords from input file. Write to output file (_clean prepended to extension).")
  parser.add_argument("infile", help="Path to the input password file.")
  parser.add_argument("-o", "--outfile", default=None, help="Optional output file path. If omitted, derive by inserting _clean before the extension.")
  parser.add_argument("-n", "--numhashes", dest="num_hashes", type=int, default=None, help="Number of hashes to remove (overrides autodetect).")
  parser.add_argument("-l", "--log", dest="log_fixes", action="store_true", help="Log bad/fixed lines to a .log file (named from the output file name).")
  parser.add_argument("-s", "--stripcount", dest="strip_count", action="store_true", help="Strip the password count, if any, from the output.")
  parser.add_argument("-m", "--mojibake_ok", dest="fix_mojibake", action="store_false", default=True, 
      help="Allow mojibake through unchanged. Disables default ftfy and extra mojibake fixes and speeds up processing.")   # will still be counted and (optionally) logged
  # parser.add_argument("-j", "--junk_ok", dest="strip_junk", action="store_false", default=True, help="Keep suspected junk lines (mostly non-ASCII) instead of default removal. Speeds up processing.")   # will still be counted and (optionally) logged
  parser.add_argument("-c", "--checkonly", dest="check_only", action="store_true", help="Check/report/log only; do not write the cleaned output file.")
  parser.add_argument("--decode-errors", choices=["report", "replace", "strict"], default="report", 
      help="Decode error handling: 'report' (default) falls back to latin-1 and reports affected lines to stdout.")
  parser.add_argument("--minlen", type=int, default=None, help=f"Minimum password length (default: {LEN_MIN}).")
  parser.add_argument("--maxlen", type=int, default=None, help=f"Maximum password length (default: {LEN_MAX}).")
  return parser.parse_args()

  # Guesstimate character encoding using chardet
  # Get encoding from ['encoding'] item of returned list, confidence = ['confidence']
def detect_charset(file):
  detector = UniversalDetector()
  with open(file, "rb") as f:
    for line in f:
      detector.feed(line)
      if detector.done:
        break
  return detector.close()

  # Flexible character decoding, based on CLI args
  # This is mostly deprecated since latin-1 fallback and ftfy.decode_text() handles the mojibake that was causing errors
  # But leaving it just in case
def decode_input_line(raw_line: bytes, encoding: str, decode_errors: str, infile: str, line_num: int):
  try:
    if decode_errors == "replace":
      return raw_line.decode(encoding, errors="replace"), False
    return raw_line.decode(encoding), False
  except UnicodeDecodeError as exc:
    if decode_errors == "strict":
      raise SystemExit(f"\nDecode error in {infile} at line {line_num}: {exc}.") from exc
    return raw_line.decode("latin-1"), True   # fall back to latin-1, since it has the fewest invalid codepoints


  # Check for additional likely mojibake that ftfy.decode_text() doesn't catch
def more_mojibake(text: str):
  if not text:
    return text

    # Unwrap common nested mojibake such as Ð“Â§ -> Г§ -> ç
    # Typically from utf-8 being misread as latin-1 or cp1252
  if SUSPICIOUS_UTF8_RE.search(text):   # quick check for speed, since  most lines won't have mojibake
    marker_count = sum(text.count(marker) for marker in SUSPICIOUS_UTF8_MARKERS)
    if marker_count > 0:
      for _ in range(2):   # cap at 2 iterations to avoid too much weirdness
        changed = False
        for encoding in ("latin-1", "cp1252"):
          try:
            candidate = text.encode(encoding).decode("utf-8")
          except UnicodeError:
            continue
          candidate_marker_count = sum(candidate.count(marker) for marker in SUSPICIOUS_UTF8_MARKERS)
          if candidate != text and candidate_marker_count < marker_count:
            text = candidate
            marker_count = candidate_marker_count
            changed = True
            break
        if not changed:
          break

    # Check for common UTF-7
  if UTF7_MARKER in text:   # quick check for speed
    for token, replacement in UTF7_FIXES.items():
      if token in text:
        text = text.replace(token, replacement)

    # Check for encoding goofs with Cyrillic text, typically utf-8 misread as cp1251
    # But only when text contains Cyrillic codepoints and suspicious sequences 
    # or a strong Latin-to-Cyrillic imbalance (to avoid touching normal Cyrillic).
    # Note: Cyrillic could have been exposed by the UTF-8 fix above, so this check happens second
  if CYRILLIC_RE.search(text):  # quick check for speed, since most lines won't have Cyrillic
    cyrillic_count = sum(1 for ch in text if "\u0400" <= ch <= "\u04FF")   # Cyrillic codepoints
    if cyrillic_count == 0:
      return text
    ascii_alpha_count = sum(1 for ch in text if ch.isascii() and ch.isalpha())
    if (ascii_alpha_count < cyrillic_count * 2) and not any(pair in text for pair in SUSPICIOUS_CYRILLIC):
      return text
    try:
      text = text.encode("cp1251").decode("utf-8")   # attempt fix by decoding as UTF-8 then encode as cp1251
    except UnicodeError:
      return text

  return text
  

  # *** Not using ***
  # *** Obsoleted by find_junk_pws.py
  # Determine if line is junk, based on heuristics
  # Assume only called if line length is at least 32 chars
def junk_line(line: str):
    # 16 or more pairs of hex digits (32+ hex chars), trailing chars ok
  if len(line) < 32:
    return False
  if LONG_HEX_RE.match(line):
    return True
    # Suspicious markup patterns (could be from HTML or XML dumps, etc.)
    # How slow is this?? Maybe check for '<' '&' and '=' (or typical code punct) first for speed
  if any(marker in line for marker in ("<input", "<param", "<img", "href=", "src=", "alt=\"", "title=\"", "type=\"submit", "value=\"", "style_left=", "slideshowTime:", "so.addParam(", "aTag.", 'target="_blank"', 'mso-style-name:')):
    return True
    # High proportion of non-ASCII extended chars and very few ASCII alphanumerics (to avoid normal non-Latin passwords)
    # Not sure this works. Maybe check for anything that's not ~90% Unicode script range if > 255?
    # Might need shortcut check for not ASCII, for speed (but make sure comes after HTML and code check)
  ascii_alnum = sum(1 for ch in line if ch.isascii() and ch.isalnum())
  if ascii_alnum <= 1 and len(line) > 0 and sum(1 for ch in line if not ch.isascii() or ch.isalnum()) / len(line) >= 0.8:
    return True

  # Detect trailing count delimiter by looking for the last non-digit, non-space character in the line
def detect_end_count_delimiter(line: str):
  i = len(line) - 1
  saw_digit = False
  while i >= 0 and (line[i].isdigit() or line[i] == " "):
    if line[i].isdigit():
      saw_digit = True
    i -= 1
  if not saw_digit or i < 0:
    return None
  if line[i] in {",", "|", "\t"}:
    return line[i]
  return None

  # Detect leading count delimiter after optional left space padding.
def detect_begin_count_delimiter(line: str):
  stripped = line.lstrip(" ")
  i = 0
  while i < len(stripped) and stripped[i].isdigit():
    i += 1
  if i == 0 or i >= len(stripped):
    return None
  if stripped[i] in {" ", ",", "|", "\t"}:
    return stripped[i]
  return None

def detect_count_format(line: str):
  line = line.rstrip('\r\n')   # strip any trailing newline before inspecting the end of the line
  end_delim = detect_end_count_delimiter(line)
  if end_delim is not None:
    return ("end", end_delim)
  begin_delim = detect_begin_count_delimiter(line)
  if begin_delim is not None:
    return ("beginning", begin_delim)
  return None

  # Split off count using position and delimiter
  # Return (password, count) or (None, 0) if count is not valid
def split_count(text: str, pos: str, delim: str):
  if pos == "end":
    pw, sep, count_str = text.rpartition(delim)
  elif pos == "beginning":
    count_str, sep, pw = text.lstrip(" ").partition(delim)   # strip leading spaces before partitioning, since count might be left-padded
  else:
    raise ValueError(f"split_count: unknown pos {pos!r}")
  if not sep:
    return None, 0
  count_str = count_str.strip()
  if not count_str.isdigit():
    return None, 0
  count = int(count_str)
  if count <= 0:
    return None, 0
  return pw, count

  # Decode $HEX[...] anywhere in the string, case-insensitively, including nesting
  # Note: technically $[HEX] should be alone on the line, but nobody follows the rules
  #       missing end ] is common, so handle that too
def decode_hex(pw: str):
  marker = HEX_MARKER_RE.search(pw)
  if marker is None:
    return pw, 0
  end_bracket = pw.find("]", marker.end())
  if end_bracket == -1:   # no closing bracket, assume end of line (if bad, fromhex will catch it, which is fine)
    end_bracket = len(pw)
  try:
    decoded_bytes = bytes.fromhex(pw[marker.end():end_bracket])
  except ValueError:
    return pw, 1   # decode failure, set bad-hex return count to 1
  try:
    decoded_pw = decoded_bytes.decode("utf-8")   # decode as UTF-8 first, then fall back to Latin-1
  except UnicodeDecodeError:
    decoded_pw = decoded_bytes.decode("latin-1")
  decoded_line = pw[:marker.start()] + decoded_pw + pw[end_bracket + 1:]
  if HEX_MARKER_RE.search(decoded_line):   # check for nested or repeated $HEX encoding, call self
    return decode_hex(decoded_line)

  return decoded_line, 0


  # Check if a line appears to have email:password format
def looks_like_email(line: str):
  at_pos = line.find("@")
  if at_pos > 0:
    delim_pos = -1
    for i in range(at_pos + 1, len(line)):
      if line[i] in ":;":
        delim_pos = i
        break
    if delim_pos != -1:
      domain = line[at_pos + 1:delim_pos]
      if domain and "." in domain and not domain.startswith(".") and not domain.endswith("."):
        return True
  return False


  # Check if a line appears to have hash:[hash: | salt: ...]password format
def looks_like_hash(line: str):
  hash_count = 0
  parts = line.split(":")
  while hash_count < len(parts) - 1 and parts[hash_count] and parts[hash_count].isalnum():
    hash_count += 1
  if hash_count > 0 and hash_count < len(parts):
    return hash_count
  return 0

  # Check if password is a hash (garbage data common in .found files)
  # Return index of matching hash pattern, or None if no match
  # (Note: not currently using index, but could be useful for stats)
  # Loop through hash patterns (ordered by approx. expected frequency) for matches
def is_hash(pw: str) -> int | None:
    length = len(pw)
    for idx, (min_length, max_length, pattern) in enumerate(HASH_PATTERNS):
        if length < min_length:
            continue
        if length > max_length:
            continue
        if pattern.match(pw):
            return idx
    return None


###############
### Helpers ###

  # Build the stats dict; cleanup-specific keys only included when cleanup=True
def make_stats(cleanup: bool = False) -> dict:
  stats = {
    "total_lines": 0,
    "pw_lines": 0,
    "num_pws": 0,
    "short_pw_lines": 0,
    "long_pw_lines": 0,
    "ctrl_lines": 0,
    "bad_count_lines": 0,
    "total_pw_length": 0,
  }
  if cleanup:
    stats.update({
      "bad_hash_lines": 0,
      "colon_lines": 0,
      "semicolon_lines": 0,
      "hex_lines": 0,
      "bad_hex_lines": 0,
      "uncracked_lines": 0,
      "hex_escaped_lines": 0,
      "html_escaped_lines": 0,
      "mojibake_lines": 0,
      "junk_lines": 0,
      "corrupt_lines": 0,
      "bad_encoding_lines": 0,
    })
  return stats

  # Open log file and write header; returns open file handle, or None if log not requested
def open_log(logfile: str, infile: str):
  f_log = open(logfile, "w", encoding="utf-8-sig", newline="")
  wall_clock = datetime.now().strftime("%Y-%m-%d %H:%M")
  f_log.write(f"{wall_clock} clean_pws.py log for {infile}\n")
  return f_log


  # Write log entry
  # Escape invisible/problematic Unicode codepoints for readability
  # Keep printable glyphs unchanged so mojibake fixes are easy to inspect
def write_log(f_log, lnum, info: str, line: str):
  out = []
  for ch in line:
    cp = ord(ch)
    cat = unicodedata.category(ch)

      # Escape controls/format chars plus uncommon separators/spaces.
    escape = (
      cat in {"Cc", "Cf", "Cs", "Zl", "Zp"}
      or (cat == "Zs" and ch != " ")
    )
    if not escape:
      out.append(ch)
      continue
    if cp <= 0xFF:       # ASCII
      out.append(f"\\x{cp:02x}")
    elif cp <= 0xFFFF:   # Unicode basic multilingual plane (BMP)
      out.append(f"\\u{cp:04x}")
    else:                # Unicode supplementary planes
      out.append(f"\\U{cp:08x}")
  f_log.write(f"{lnum}\t{info}:\t{''.join(out)}\n")


  # Strip email/hash prefix and split off count; return (pw, pw_count) or (None, 0) to skip line
def isolate_password(clean_line: str, config: dict, stats: dict, f_log, lnum: int):
  has_email = config["has_email"]
  num_hashes = config["num_hashes"]
  count_pos = config["count_pos"]

    # Strip email:password or hash:/salt:password formats
  if has_email:
    first_colon = clean_line.find(':')
    if first_colon != -1:
      pw = clean_line[first_colon + 1:]
      stats["colon_lines"] += 1
    else:
      if clean_line.count(';') == 1:
        pw = clean_line[clean_line.find(';') + 1:]
        stats["semicolon_lines"] += 1
      else:
        return None, 0
  elif num_hashes > 0:
    parts = clean_line.split(':')
    if len(parts) <= num_hashes:
      stats["bad_hash_lines"] += 1
      return None, 0
    pw = ':'.join(parts[num_hashes:])
  else:
    pw = clean_line

    # Process any password count for cleaned output and for counting total number of passwords
  pw_count = 1
  if count_pos is not None:
    pw, pw_count = split_count(pw, count_pos, config["count_delim"])
    if pw is None:
      stats["bad_count_lines"] += 1
      if f_log is not None:
        write_log(f_log, lnum, "Bad count", clean_line)
      return None, 0

  return pw, pw_count


  # Apply all decode/fix passes to a password string; return cleaned pw, or None to skip line
def clean_password_line(pw: str, config: dict, stats: dict, f_log, lnum: int):
  fix_mojibake = config["fix_mojibake"]
  len_min = config["len_min"]
  len_max = config["len_max"]

    # Handle hashcat-style hex encoding $HEX[...]) and leftover unmatched hashes (common in .found file)
    # Needs to come before hex escape conversion, stripping controls, decoding char refs, and encode fix since key chars might be hex encoded
  if '$' in pw:   # Quick check for speed
    if HEX_MARKER_RE.search(pw):
      stats["hex_lines"] += 1
      pw, bad_hex = decode_hex(pw)
      stats["bad_hex_lines"] += bad_hex
      if bad_hex == 1:
        if f_log is not None:
          write_log(f_log, lnum, "Malhex", pw)   # only log bad hex; don't clog the log with too many $HEX[] lines
        return None
    elif pw[0] == '$':   # starts with $, check if hash instead of password (don't clog the log, could be millions)
      if is_hash(pw) is not None:
        stats["uncracked_lines"] += 1
        return None

    # Convert any valid \x hex escaped chars, leave malformed ones untouched
    # Needs to come before stripping controls, decoding char refs, and encode fix since key chars might be hex encoded
  if "\\x" in pw:   # convert valid \xnn escape sequences, leave malformed ones untouched
    old_pw = pw
    pw = HEX_ESCAPE_RE.sub(lambda match: bytes.fromhex(match.group(1)).decode("latin-1"), pw)
    if pw != old_pw:
      stats["hex_escaped_lines"] += 1
      if f_log is not None:
        write_log(f_log, lnum, "Hex", f"{old_pw}  =>  {pw}")

    # Decode escaped HTML character references like &amp;
  any_escaped = 0
  while ('&' in pw):   # while loop to handle nested encodings (note: used to check for ';' but that overrode more relaxed unescape)
    unescaped_pw = unescape(pw)
    if unescaped_pw == pw:
      break
    any_escaped = 1
    pw = unescaped_pw
  stats["html_escaped_lines"] += any_escaped

    # Apply ftfy fixes, if enabled (Note: this comes after own HTML char ref decode)
    # Defaults:
    #   "fix_encoding": True,
    #   "restore_byte_a0": True,
    #   "replace_lossy_sequences": True,
    #   "decode_inconsistent_utf8": True,
    #   "fix_c1_controls": True,
    # Then follow up with a few additional fixes
    # Start with quick check for speed, since most lines are ASCII and won't have mojibake or UTF-7 issues
  if fix_mojibake and ((not pw.isascii()) or (UTF7_MARKER in pw)):
    fixed_pw = fix_encoding(pw)
    log_fix = 'Mojibake'
    more_fixed_pw = more_mojibake(fixed_pw)   # second pass for stuff ftfy misses
    if more_fixed_pw != fixed_pw:
      fixed_pw = more_fixed_pw
      log_fix += "+"   # flag extra fix in log ("Mojibake+"), so we can track need for second pass
    if fixed_pw != pw:
      stats["mojibake_lines"] += 1
      if (f_log is not None) and (not '\ufffd' in fixed_pw):   # (don't double log mojibake fix if corrupt, logged below)
        write_log(f_log, lnum, log_fix, f"{pw}  =>  {fixed_pw}")
      pw = fixed_pw

    # Check for bad encoding (replacement char) after decodes (may be hex encoded) and fixes (ftfy can add it)
    # or could already be in the file
  if '\ufffd' in pw:
    stats["corrupt_lines"] += 1   # or a dedicated counter
    if f_log is not None:
      write_log(f_log, lnum, 'Corrupt', f"{pw}")
    return None
  
    # Remove all the control chars (Cc and Cf)
    # Do at this late stage because decode steps above can introduce control chars such as newlines from &#10;, \x0a, or $HEX[0a]
    # Tabs are ok to remove now, since any count delimiter tab was already split off upstream
  no_ctrl_pw = pw.translate(STRIP_CTRLS)
  if len(no_ctrl_pw) < len(pw):
    stats["ctrl_lines"] += 1
    pw = no_ctrl_pw
  
    # Too short or too long?
  if len(pw) < len_min:
    stats["short_pw_lines"] += 1
    return None
  if len(pw) > len_max:
    stats["long_pw_lines"] += 1
    if f_log is not None:
      write_log(f_log, lnum, f">{len_max}", pw)
    return None

  return pw

  # Print stats summary; all keys present in dict are printed; a subset are gated on > 0
def print_stats(stats: dict, config: dict, elapsed_seconds: float):
  len_min = config["len_min"]
  len_max = config["len_max"]
  wall_clock = datetime.now().strftime("%Y-%m-%d %H:%M")
  print(f"\r== Info ==  ({wall_clock}){" " * 30}")   # Note: this overwrites the progress line (ok, since we're done), thus the extra spaces
  print(f"Elapsed time: {int(elapsed_seconds//3600):02}:{int((elapsed_seconds%3600)//60):02}:{int(elapsed_seconds%60):02}")
  # print(f"Encoding: {config['file_encoding']} ({config['file_enc'].get('confidence', 0.0):.0%} conf.)")
  print(f"Total lines: {stats['total_lines']:,}")

  print(f"Corrected lines ...")   # the ifs avoid errors with skipped stats from command-line options
  # if stats.get("bad_encoding_lines", 0) > 0:
  #   print(f"  Decode fallbacks: {stats['bad_encoding_lines']:,}")
  print(f"  Control character(s): {stats['ctrl_lines']:,}")
  if "colon_lines" in stats:
    print(f"  Colon delimiter: {stats['colon_lines']:,}")
  if "semicolon_lines" in stats:
    print(f"  Semicolon delimiter: {stats['semicolon_lines']:,}")
  if "hex_lines" in stats:
    print(f"  Hex enc ($HEX): {stats['hex_lines']:,}")
  if "hex_escaped_lines" in stats:
    print(f"  Escaped hex (\\x): {stats['hex_escaped_lines']:,}")
  if "html_escaped_lines" in stats:
    print(f"  Escaped HTML (&): {stats['html_escaped_lines']:,}")
  if "mojibake_lines" in stats:
    print(f"  Mojibake: {stats['mojibake_lines']:,}")

  print(f"Skipped lines ...")
  if stats.get("bad_hash_lines", 0) > 0:
    print(f"  Mismatched number of hashes: {stats['bad_hash_lines']:,}")
  if stats.get("bad_count_lines", 0) > 0:
    print(f"  Invalid count: {stats['bad_count_lines']:,}")
  if stats.get("bad_hex_lines", 0) > 0:
    print(f"  Malformed hex: {stats['bad_hex_lines']:,}")
  if stats.get("junk_lines", 0) > 0:
    print(f"  Junk: {stats['junk_lines']:,}")
  if stats.get("corrupt_lines", 0) > 0:
    print(f"  Corrupt: {stats['corrupt_lines']:,}")
  if stats.get("uncracked_lines", 0) > 0:
    print(f"  Uncracked hash: {stats['uncracked_lines']:,}")
  print(f"  Too short (<{len_min}): {stats['short_pw_lines']:,}")
  print(f"  Too long (>{len_max}): {stats['long_pw_lines']:,}")
  print(f"Good passwords: {stats['pw_lines']:,}")
  if stats['pw_lines'] != stats['num_pws']:
    print(f"Total password count: {stats['num_pws']:,}")
  if stats.get("total_pw_length") and stats.get("pw_lines"):
    avg_len = stats["total_pw_length"] / stats["pw_lines"]
    print(f"Average length: {avg_len:.1f}")

###########################
### -- Initial stuff -- ###

def preprocess(args):
  infile = args.infile
  outfile = args.outfile

    # Initialize autodetections
  num_hashes = args.num_hashes if args.num_hashes is not None else 0
  sampled = 0
  email_like = 0
  colon_like = 0
  hash_hits = {}
  count_pos = None
  count_delim = None
  count_hits = {}
  has_email = False
  detected_hashes = 0

    # Try to determine file encoding
  file_enc = detect_charset(infile)
  file_encoding = file_enc.get("encoding") or "utf-8"
  # TODO: revisit this: just rely on the fallback in decode_input_line()? (but update it with the Windows-1252 preliminary fallback?)
  if file_encoding in ['utf-7', 'cp437']:
    file_encoding = "latin-1"   # workaround for chardet wrong guesses (latin-1 has fewest invalid codepoints)
  if file_encoding.startswith("Windows-"):
    file_encoding = "Windows-1252"   # workaround for chardet; probably any Windows encoding is 1252

    # First pass: sample up to SAMPLE_LINES lines to detect email format, count format, etc.
  with open(infile, "r", encoding=file_encoding, errors="ignore", newline="") as f:
    for line in f:
      if line.strip() == "":
        continue
      line_count = detect_count_format(line)
      sampled += 1
      colon_like += ':' in line
      if looks_like_email(line):
        email_like += 1
      else:
        hash_count = looks_like_hash(line)
        if hash_count > 0:
          hash_hits[hash_count] = hash_hits.get(hash_count, 0) + 1
      if line_count is not None:
        count_hits[line_count] = count_hits.get(line_count, 0) + 1
      if sampled >= SAMPLE_LINES:
        break

    # Done sampling, check results and set flags, etc.
  if sampled > 0 and (email_like / sampled) >= DETECT_THRESHOLD:   # do enough lines have an email prefix in them?
    has_email = True
  elif sampled > 0 and colon_like == sampled and hash_hits:   # do all lines have a colon and seem to be hashes or salts?
    non_uncracked_lines = sampled - sum(hash_hits.values())
    if (len(hash_hits) > 1) or (non_uncracked_lines > 0):
      details = ", ".join(f"{hash_count}:{hits}" for hash_count, hits in sorted(hash_hits.items()))
      if non_uncracked_lines > 0:
        details = f"{details}, no-hash:{non_uncracked_lines}" if details else f"no-hash:{non_uncracked_lines}"
      raise SystemExit(f"Mixed hash count in sampled lines: {details}.")
    detected_hashes = next(iter(hash_hits))
    if args.num_hashes is None:
      num_hashes = detected_hashes

  if sampled > 0 and count_hits:
    (best_pos, best_delim), best_hits = max(count_hits.items(), key=lambda kv: kv[1])
    if (best_hits / sampled) >= DETECT_THRESHOLD:
      count_pos = best_pos
      count_delim = best_delim

  if has_email:
    print(f"* Detected email:password format. Stripping email prefixes.")
  elif detected_hashes > 0:
    print(f"* Detected {detected_hashes} hash{'es' if detected_hashes != 1 else ''} before passwords. Stripping.")
  if count_pos is not None:
    print(f"* Detected password count at {count_pos}, delimiter = {count_delim!r}.")

  if outfile is None:
    dot = infile.rfind(".")
    if dot == -1:
      outfile = f"{infile}_clean"
    else:
      outfile = f"{infile[:dot]}_clean{infile[dot:]}"

  logfile = str(Path(outfile).with_suffix(".log"))

  return {
    "infile": infile,
    "outfile": outfile,
    "logfile": logfile,
    "num_hashes": num_hashes,
    "strip_count": args.strip_count,
    "fix_mojibake": args.fix_mojibake,
    # "strip_junk": args.strip_junk,
    "log_fixes": args.log_fixes,
    "check_only": args.check_only,
    "decode_errors": args.decode_errors,
    "has_email": has_email,
    "count_pos": count_pos,
    "count_delim": count_delim,
    "file_enc": file_enc,
    "file_encoding": file_encoding,
    "len_min": args.minlen if args.minlen is not None else LEN_MIN,
    "len_max": args.maxlen if args.maxlen is not None else LEN_MAX,
  }

#################
### main loop ###

def clean_em_up(config):
  stats = make_stats(cleanup=True)

  write_buf = []   # initialize buffer, store to buffer and write in chunks to increase speed
  lnum = 0   # line counter for main loop
  bytes_read = 0
  total_bytes = max(1, Path(config["infile"]).stat().st_size)
  start_time = time.perf_counter()
  PROGRESS_INTERVAL = 4.0   # update progress line every n seconds
  next_progress_time = start_time
  f_out = None   # initialize output file handle; will not be opened if check_only arg is set
  f_log = None   # initialize log file handle; will only be opened if log_fixes arg is set

  with open(config["infile"], "rb") as f_in:   # read raw bytes for flexible decoding (see decode_input_line below)
      # Copy key config values to local vars for speed inside loop
    count_pos = config["count_pos"]
    check_only = config["check_only"]

    if not check_only:
      f_out = open(config["outfile"], "w", encoding="utf-8", newline="")
    if config["log_fixes"]:
      f_log = open_log(config["logfile"], config["infile"])


    for raw_line in f_in:
      lnum += 1

      bytes_read += len(raw_line)
      if lnum % 10_000 == 1:   # only check time for progress every 10,000 lines, for speed (avoid calling time.perf_counter())
        now = time.perf_counter()
        if now >= next_progress_time:   # time to show a progress update
          fraction_done = min(bytes_read / total_bytes, 1.0)
          percent_done = fraction_done * 100
            # wait a few intervals to get accurate estimate (+ div by 0 safety check)
          if (now >= start_time + PROGRESS_INTERVAL * 3) and (fraction_done > 0):
            elapsed = now - start_time
            eta_seconds = int(max(0, elapsed * (1 - fraction_done) / fraction_done))
            eta = f"Est. remaining: {eta_seconds//3600:02}:{(eta_seconds%3600)//60:02}:{eta_seconds%60:02}"
          else:
            eta = ""
          print(f"\rProcessing line {lnum:,} ({percent_done:.0f}%) {eta}", end="", flush=True)
          next_progress_time = now + PROGRESS_INTERVAL

      line, had_decode_error = decode_input_line(
        raw_line, config["file_encoding"], config["decode_errors"], config["infile"], lnum
      )
      if had_decode_error:
        stats["bad_encoding_lines"] += 1
#        if f_log is not None:
#          f_log.write(f"{lnum}\tDecode error: {line!r}\n")

      pw, pw_count = isolate_password(line.rstrip('\r\n'), config, stats, f_log, lnum)
      if pw is None:
        continue

      # TODO: most of the 197,908 ignored lines in breachcomp2 are crap, but some have a single tab delimiter (about 21,251)
      # so consider adding tab delimiter support later

      pw = clean_password_line(pw, config, stats, f_log, lnum)
      if pw is None:
        continue

        # After all the decoding and fixes, check if the line looks like junk and skip it (unless not stripping junk)
        # Only long lines, for speed, and since most junk lines are long and most short lines aren't junk
        # (Note: lines > LEN_MAX are already skipped)
      # Disabled for now, since it's not catching most junk, and it slows things down
      # if strip_junk and len(pw) >= 20:
      #   if junk_line(pw):
      #     stats["junk_lines"] += 1
      #     if f_log is not None:
      #       f_log.write(f"{lnum}\tJunk:\t{pw}\n")
      #     continue

      stats["pw_lines"] += 1
      stats["num_pws"] += pw_count
      stats["total_pw_length"] += len(pw)

        # Done cleaning, write out the shiny, pink, password
        # If counts, use tab delimiter
      if not check_only:
        if (count_pos is not None) and (not config["strip_count"]):
          write_buf.append(f"{pw}\t{pw_count}\n")
        else:
          write_buf.append(f"{pw}\n")

        if len(write_buf) >= WRITE_BUFFER_SIZE:
          f_out.writelines(write_buf) # type: ignore
          write_buf.clear()

    if f_out is not None and write_buf:
      f_out.writelines(write_buf)

    stats["total_lines"] = lnum

  return stats


def main():
  args = parse_args()

  if args.check_only:
    print(f"Analyzing passwords in {args.infile} (no cleaned output)")
  else:
    print(f"Cleaning passwords in {args.infile}")

  config = preprocess(args)

  if config["log_fixes"]:
    print(f"Logging changes to {config['logfile']}")

  if not args.check_only:
    print(f"Writing UTF-8 to {config['outfile']}")

  start_time = time.perf_counter()
  stats = clean_em_up(config)
  elapsed_seconds = time.perf_counter() - start_time

  print_stats(stats, config, elapsed_seconds)


if __name__ == "__main__":
  main()
