/* Copyright (C) The IETF Trust (2007).  This version of
   sample C code is part of RFC XXXX; see the RFC itself
   for full legal notices.

   Regarding this sample C code (or any portion of it), the authors
   make no guarantees and are not responsible for any damage
   resulting from its use.  The authors grant irrevocable permission
   to anyone to use, modify, and distribute it in any way that does
   not diminish the rights of anyone else to use, modify, and
   distribute it, provided that redistributed derivative works do
   not contain misleading author or version information.

   Derivative works need not be licensed under similar terms.
 */

#include <stdio.h>
#include <string.h>

#include "imapurl.h"

/* hexadecimal lookup table */
static const char hex[] = "0123456789ABCDEF";

#define XX 127

/* "gen-delims" excluding "/" but including "%" */
#define GENERAL_DELIMS_NO_SLASH     ":?#[]@" "%"

/* "gen-delims" (excluding "/", but including "%")
   plus subset of "sub-delims" */
#define GENERAL_UNSAFE_NO_SLASH     GENERAL_DELIMS_NO_SLASH ";&=+"
#define OTHER_UNSAFE                " \"<>\\^`{|}"

/* URL unsafe printable characters */
static const char mailbox_url_unsafe[] = GENERAL_UNSAFE_NO_SLASH
                                         OTHER_UNSAFE;

/* UTF7 modified base64 alphabet */
static const char base64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

#define UNDEFINED 64

/* UTF16 definitions */
#define UTF16MASK   0x03FFUL
#define UTF16SHIFT  10
#define UTF16BASE   0x10000UL
#define UTF16HIGHSTART   0xD800UL
#define UTF16HIGHEND     0xDBFFUL
#define UTF16LOSTART     0xDC00UL
#define UTF16LOEND  0xDFFFUL

/* Convert an IMAP mailbox to a URL path
 *  dst needs to have roughly 4 times the storage space of src
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 */
void imap_mailbox_to_url(char *dst, const char *src)
{
    unsigned char c, i, bitcount;
    unsigned long ucs4, utf16, bitbuf;
    unsigned char base64[256], utf8[6];

    /* initialize modified base64 decoding table */
    memset(base64, UNDEFINED, sizeof (base64));
    for (i = 0; i < sizeof (base64chars); ++i) {
     base64[(int) base64chars[i]] = i;
    }

    /* loop until end of string */
    while (*src != '\0') {
     c = *src++;
     /* deal with literal characters and &- */
     if (c != '&' || *src == '-') {
         /* NB: There are no "URL safe" characters after the '~' */
         if (c < ' ' || c > '~' ||
             strchr(mailbox_url_unsafe, c) != NULL) {
          /* hex encode if necessary */
          dst[0] = '%';
          dst[1] = hex[c >> 4];
          dst[2] = hex[c & 0x0f];
          dst += 3;
         } else {
          /* encode literally */
          *dst++ = c;
         }
         /* skip over the '-' if this is an &- sequence */
         if (c == '&') ++src;

     } else {
        /* convert modified UTF-7 -> UTF-16 -> UCS-4 -> UTF-8 -> HEX */
         bitbuf = 0;
         bitcount = 0;
         ucs4 = 0;
         while ((c = base64[(unsigned char) *src]) != UNDEFINED) {
          ++src;
          bitbuf = (bitbuf << 6) | c;
          bitcount += 6;
          /* enough bits for a UTF-16 character? */
          if (bitcount >= 16) {
              bitcount -= 16;
              utf16 = (bitcount ? bitbuf >> bitcount
                             : bitbuf) & 0xffff;
              /* convert UTF16 to UCS4 */
              if
                    (utf16 >= UTF16HIGHSTART && utf16 <= UTF16HIGHEND) {
               ucs4 = (utf16 - UTF16HIGHSTART) << UTF16SHIFT;
               continue;
              } else if
                    (utf16 >= UTF16LOSTART && utf16 <= UTF16LOEND) {
               ucs4 += utf16 - UTF16LOSTART + UTF16BASE;
              } else {
               ucs4 = utf16;
              }
              /* convert UTF-16 range of UCS4 to UTF-8 */
              if (ucs4 <= 0x7fUL) {
               utf8[0] = (unsigned char) ucs4;
               i = 1;
              } else if (ucs4 <= 0x7ffUL) {
               utf8[0] = 0xc0 | (unsigned char) (ucs4 >> 6);
               utf8[1] = 0x80 | (unsigned char) (ucs4 & 0x3f);
               i = 2;
              } else if (ucs4 <= 0xffffUL) {
               utf8[0] = 0xe0 | (unsigned char) (ucs4 >> 12);
               utf8[1] = 0x80 | (unsigned char) ((ucs4 >> 6) & 0x3f);
               utf8[2] = 0x80 | (unsigned char) (ucs4 & 0x3f);
               i = 3;
              } else {
               utf8[0] = 0xf0 | (unsigned char) (ucs4 >> 18);
               utf8[1] = 0x80 | (unsigned char) ((ucs4 >> 12) & 0x3f);
               utf8[2] = 0x80 | (unsigned char) ((ucs4 >> 6) & 0x3f);
               utf8[3] = 0x80 | (unsigned char) (ucs4 & 0x3f);
               i = 4;
              }
              /* convert utf8 to hex */
              for (c = 0; c < i; ++c) {
               dst[0] = '%';
               dst[1] = hex[utf8[c] >> 4];
               dst[2] = hex[utf8[c] & 0x0f];
               dst += 3;
              }
          }
         }
         /* skip over trailing '-' in modified UTF-7 encoding */
         if (*src == '-') ++src;
     }
    }
    /* terminate destination string */
    *dst = '\0';
}
