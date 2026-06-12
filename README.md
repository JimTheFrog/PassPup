# ALIEN - Attack likelihood inference engine nexus
Modular password strength estimator, including real-world attack simulation.

Stay tuned...

In the meantime, here's my password cleaning utility (requires Python 3 + `chardet` and `ftfy` libs):
- Autodetects if lines are in email:password or email;password format and strips
- Autodetects one or more hashes/salts in front of password and strips
- Autodetects if lines have password count at beginning or end of line, outputs at end with <tab> delimiter (or strips if args flag set)
- Recognizes incoming encoding (using chardet), always writes in UTF-8
- Removes ctrl chars and too-short and too-long passwords
- Converts HTML character references and $HEX[...] sequences, including nesting
- Fixes character encoding errors (mojibake) with ftfy and additional heuristics
- Logs mojibake fixes, malformed $HEX[], and other stuff if requested
- Recognizes hashes instead of passwords (common in .found files) and skips them

```
usage: clean_pws.py [-h] [-o OUTFILE] [-n NUM_HASHES] [-l] [-s] [-m] [-c] [--decode-errors {report,replace,strict}]
                    [--minlen MINLEN] [--maxlen MAXLEN]
                    infile

Clean passwords from input file. Write to output file (_clean prepended to extension).

positional arguments:
  infile                Path to the input password file.

options:
  -h, --help            show this help message and exit
  -o, --outfile OUTFILE
                        Optional output file path. If omitted, derive by inserting _clean before the extension.
  -n, --numhashes NUM_HASHES
                        Number of hashes to remove (overrides autodetect).
  -l, --log             Log bad/fixed lines to a .log file (named from the output file name).
  -s, --stripcount      Strip the password count, if any, from the output.
  -m, --mojibake_ok     Allow mojibake through unchanged. Disables default ftfy and extra mojibake fixes and speeds up
                        processing.
  -c, --checkonly       Check/report/log only; do not write the cleaned output file.
  --decode-errors {report,replace,strict}
                        Decode error handling: 'report' (default) falls back to latin-1 and reports affected lines to
                        stdout.
  --minlen MINLEN       Minimum password length (default: 4).
  --maxlen MAXLEN       Maximum password length (default: 96).
```
