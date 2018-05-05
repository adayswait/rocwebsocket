#ifndef ROC_BASE64_H
#define ROC_BASE64_H

#define BASE64_ENCODE_OUT_SIZE(s) (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s) (((s)) / 4 * 3)

int base64_encode(const unsigned char *in, unsigned int inlen, char *out);

int base64_decode(const char *in, unsigned int inlen, unsigned char *out);

#endif /* ROC_BASE64_H */
