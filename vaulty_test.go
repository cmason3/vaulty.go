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
  "bytes"
  "testing"
  "crypto/sha256"
)

func TestVaulty(t *testing.T) {
  plaintext := []byte("The Quick Brown Fox Jumped Over The Lazy Dog!")
  h_plaintext := sha256.Sum256(plaintext)

  if ciphertext, err := encrypt(plaintext, "pAssw0rD!", true, 80); err == nil {
    if nplaintext, err := decrypt(ciphertext, "pAssw0rD!"); err == nil {
      h_nplaintext := sha256.Sum256(nplaintext)
      if !bytes.Equal(h_nplaintext[:], h_plaintext[:]) {
        t.Errorf("Decrypted Plaintext Mismatch")
      }
    } else {
      t.Errorf("Unable to Decrypt Ciphertext")
    }
  } else {
    t.Errorf("Unable to Encrypt Plaintext")
  }

  plaintext = []byte("The Lazy Dog Jumped Over The Quick Brown Fox!")
  h_plaintext = sha256.Sum256(plaintext)

  if prkey, pukey, err := generateKeyPair(); err == nil {
    if epukey, err := encodeKey(pukey); err == nil {
      if depukey, err := decodeKey(epukey); err == nil {
        if ciphertext, err := encryptX25519(plaintext, depukey, true, 80); err == nil {
          if nplaintext, err := decryptX25519(ciphertext, prkey); err == nil {
            h_nplaintext := sha256.Sum256(nplaintext)
            if !bytes.Equal(h_nplaintext[:], h_plaintext[:]) {
              t.Errorf("Decrypted Plaintext Mismatch")
            }
          } else {
            t.Errorf("Unable to Decrypt Ciphertext")
          }
        } else {
          t.Errorf("Unable to Encrypt Plaintext")
        }
      } else {
        t.Errorf("Unable to Bech32m Decode Public Key")
      }
    } else {
      t.Errorf("Unable to Bech32m Encode Public Key")
    }
  } else {
    t.Errorf("Unable to Generate X25519 Key Pair")
  }
}
