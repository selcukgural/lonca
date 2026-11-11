// The character classes the grammars' scanners ask the C library for, as
// the C locale of macOS and of glibc gives them: ASCII and nothing else.
//
// musl answers from Unicode tables whatever the locale, so a file with an
// ideographic space or an accented letter in the wrong place gave one tree
// on Lonca's Linux builds and another on macOS. A parse has to be a function
// of the file alone: the auditor recomputes what a daemon on another machine
// signed. These definitions are linked whole into every Linux binary of the
// symbol engine and stand in for the C library's (build.rs).
#include <wctype.h>

#undef iswspace
#undef iswdigit
#undef iswxdigit
#undef iswupper
#undef iswlower
#undef iswalpha
#undef iswalnum

int iswspace(wint_t c) { return c == ' ' || (c >= '\t' && c <= '\r'); }

int iswdigit(wint_t c) { return c >= '0' && c <= '9'; }

int iswupper(wint_t c) { return c >= 'A' && c <= 'Z'; }

int iswlower(wint_t c) { return c >= 'a' && c <= 'z'; }

int iswalpha(wint_t c) { return iswupper(c) || iswlower(c); }

int iswalnum(wint_t c) { return iswalpha(c) || iswdigit(c); }

int iswxdigit(wint_t c) {
    return iswdigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}
