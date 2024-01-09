/*
 * Vaulty - Encrypt/Decrypt with ChaCha20-Poly1305
 * Copyright (c) 2021-2024 Chris Mason <chris@netnix.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
  "fmt"
  "strings"
)

var bech32mCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func polymod(values []byte) uint32 {
 chk := uint32(1)

 for _, v := range values {
   top := chk >> 25
   chk = (chk & 0x1ffffff) << 5
   chk = chk ^ uint32(v)

   for i := 0; i < 5; i++ {
     if bit := top >> i & 1; bit == 1 {
       chk ^= []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}[i]
     }
   }
 }
 return chk
}

func createChecksum(data []byte) []byte {
 data = append(data, []byte{0, 0, 0, 0, 0, 0}...)
 mod := polymod(data) ^ 0x2bc830a3
 ret := make([]byte, 6)

 for p := range ret {
   shift := 5 * (5 - p)
   ret[p] = byte(mod >> shift) & 31
 }
 return ret
}

func convertBits(data []byte, frombits, tobits byte, pad bool) (ret []byte, err error) {
 acc := uint32(0)
 bits := byte(0)
 maxv := byte(1 << tobits - 1)

 for idx, value := range data {
   if value >> frombits != 0 {
     return nil, fmt.Errorf("invalid data range: data[%d]=%d (frombits=%d)", idx, value, frombits)
   }
   acc = acc << frombits | uint32(value)
   bits += frombits

   for bits >= tobits {
     bits -= tobits
     ret = append(ret, byte(acc >> bits) & maxv)
   }
 }

 if pad {
   if bits > 0 {
     ret = append(ret, byte(acc << (tobits - bits)) & maxv)
   }
 } else if bits >= frombits {
   return nil, fmt.Errorf("illegal zero padding")
 } else if byte(acc << (tobits - bits)) & maxv != 0 {
   return nil, fmt.Errorf("non-zero padding")
 }
 return ret, nil
}

func encodeKey(key []byte) (string, error) {
 if values, err := convertBits(key, 8, 5, true); err == nil {
   var ret strings.Builder

   for _, p := range values {
     ret.WriteByte(bech32mCharset[p])
   }
   for _, p := range createChecksum(values) {
     ret.WriteByte(bech32mCharset[p])
   }
   return ret.String(), nil
 } else {
   return "", err
 }
}

func decodeKey(key string) (data []byte, err error) {
 for p, c := range key {
   if d := strings.IndexRune(bech32mCharset, c); d != -1 {
     data = append(data, byte(d))
   } else {
     return nil, fmt.Errorf("invalid character data part: s[%d]=%v", p, c)
   }
 }

 if polymod(data) != 0x2bc830a3 {
   return nil, fmt.Errorf("invalid checksum")
 }

 data, err = convertBits(data[:len(data) - 6], 5, 8, false)
 return data, err
}
