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
  "os"
  "io"
  "fmt"
  "bytes"
  "errors"
  "strings"
  "runtime"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "encoding/binary"
  "golang.org/x/term"
  "golang.org/x/crypto/hkdf"
  "golang.org/x/crypto/scrypt"
  "golang.org/x/crypto/curve25519"
  "golang.org/x/crypto/chacha20poly1305"
)

var Version = "1.0.0"

const (
  vaultyPrefix = "$VAULTY;"
  x25519Overhead = 1 + saltSize + curve25519.ScalarSize
  standardOverhead = 1 + saltSize + chacha20poly1305.NonceSize
  saltSize = 16
)

var kCache = make(map[string][]byte)

func main() {
  var m = os.O_RDWR
  var fileList []string
  var pukey []byte
  var prkey []byte
  var mO int

  if len(os.Args) > 1 {
    if len(os.Args) > 2 {
      fileList = append(fileList, os.Args[2:]...)
    }

    if smatch(os.Args[1], "encrypt") {
      if (len(fileList) > 1) && (fileList[0] == "-r") {
        var err error

        if pukey, err = decodeKey(fileList[1]); err != nil || len(pukey) != curve25519.ScalarSize {
          fmt.Fprintf(os.Stderr, "\033[1;31mError: Invalid Public Key\033[0m\n")
          os.Exit(0)
        }
        fileList = fileList[2:]
      }
      mO = 1
    } else if smatch(os.Args[1], "decrypt") {
      if (len(fileList) > 1) && (fileList[0] == "-k") {
        if keyfile, err := os.ReadFile(fileList[1]); err == nil {
          if i := bytes.Index(keyfile, []byte(vaultyPrefix)); i != -1 {
            prkey = keyfile[i:]
            fileList = fileList[2:]
          } else {
            fmt.Fprintf(os.Stderr, "\033[1;31mError: Invalid Key File\033[0m\n")
            os.Exit(0)
          }
        } else {
          fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Read Key File\033[0m\n")
          os.Exit(0)
        }
      }
      mO = 2
    } else if smatch(os.Args[1], "chpass") {
      mO = 4
    } else if smatch(os.Args[1], "keygen") && (len(fileList) == 1) {
      mO = 8
    } else if smatch(os.Args[1], "sha256") {
      m = os.O_RDONLY
      mO = 16
    }
  }

  if mO > 0 {
    if mO == 8 {
      if password, _ := getPassword("Vaulty Password: "); len(password) > 0 {
        if v, err := getPassword("Password Verification: "); password == v && err == nil {
          fmt.Fprintf(os.Stderr, "\n")

          if private, public, err := generateKeyPair(); err == nil {
            if epk, err := encrypt(private, password, true, 80); err == nil {
              if fh, err := os.OpenFile(fileList[0], os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600); err == nil {
                defer fh.Close()

                if pk, err := encodeKey(public); err == nil {
                  fmt.Fprintf(fh, "// Public ID: %s\n", pk)
                  fmt.Fprintf(fh, "%s\n", epk)

                  fmt.Fprintf(os.Stdout, "// Public ID: %s\n", pk)
                  fmt.Fprintf(os.Stdout, "%s\n", epk)

                } else {
                  fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Bech32m Encode Public Key\033[0m\n")
                }
              } else {
                fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
              }
            } else {
              fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Encrypt X25519 Private Key\033[0m\n")
            }
          } else {
            fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Generate X25519 Key Pair\033[0m\n")
          }
        } else {
          fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password Verification Failed\033[0m\n")
        }
      } else {
        fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password is Mandatory\033[0m\n")
      }
    } else {
      if len(fileList) > 0 {
        var password, npassword string
  
        if mO != 16 {
          if len(pukey) == 0 {
            if password, _ = getPassword("Vaulty Password: "); len(password) > 0 {
              if mO == 1 {
                if v, err := getPassword("Password Verification: "); password != v || err != nil {
                  fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password Verification Failed\033[0m\n")
                  os.Exit(0)
                }
                fmt.Fprintf(os.Stderr, "\n")
              } else if mO == 4 {
                if npassword, _ = getPassword("\nNew Vaulty Password: "); len(npassword) > 0 {
                  if v, err := getPassword("Password Verification: "); npassword != v || err != nil {
                    fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password Verification Failed\033[0m\n")
                    os.Exit(0)
                  }
                  fmt.Fprintf(os.Stderr, "\n")
                } else {
                  fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password is Mandatory\033[0m\n")
                  os.Exit(0)
                }
              } else {
                fmt.Fprintf(os.Stderr, "\n")
              }
            } else {
              fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password is Mandatory\033[0m\n")
              os.Exit(0)
            }
  
            if len(prkey) > 0 {
              var err error
              if prkey, err = decrypt(prkey, password); err != nil {
                fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Unable to Decrypt Private Key\033[0m\n")
                os.Exit(0)
              }
            }
          }
        }
  
        for _, fn := range fileList {
          if fh, err := os.OpenFile(fn, m, 0000); err == nil {
            defer fh.Close()
  
            if mO == 16 {
              h := sha256.New()
              if _, err := io.Copy(h, fh); err == nil {
                fmt.Fprintf(os.Stdout, "%x  %s\n", h.Sum(nil), fn)
              } else {
                fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
              }
            } else {
              if s, err := fh.Stat(); err == nil {
                rbytes := make([]byte, 16384)
                data := make([]byte, 0, s.Size() + x25519Overhead + chacha20poly1305.Overhead)
  
                for {
                  if n, err := fh.Read(rbytes); err != io.EOF {
                    data = append(data, rbytes[:n]...)
                  } else {
                    break
                  }
                }
  
                if mO == 1 {
                  var ciphertext []byte
                  var err error

                  fmt.Fprintf(os.Stdout, "Encrypting %s... ", fn)

                  if len(pukey) > 0 {
                    ciphertext, err = encryptX25519(data, pukey, false, 0)
                  } else {
                    ciphertext, err = encrypt(data, password, false, 0)
                  }

                  if err == nil {
                    fh.Truncate(int64(len(ciphertext)))
                    fh.WriteAt(ciphertext, 0)
                    fmt.Fprintf(os.Stdout, "\033[1;32mok\033[0m\n")
                    fh.Close()
  
                    if err := os.Rename(fn, fn + ".vlt"); err != nil {
                      fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
                    }
                  } else {
                    fmt.Fprintf(os.Stdout, "\033[1;31mfailed\033[0m\n")
                  }
                } else if mO == 2 || mO == 4 {
                  var plaintext []byte
                  var err error

                  fmt.Fprintf(os.Stdout, "Decrypting %s... ", fn)

                  if len(prkey) > 0 {
                    plaintext, err = decryptX25519(data, prkey)
                  } else {
                    plaintext, err = decrypt(data, password)
                  }

                  if err == nil {
                    if mO == 4 {
                      fmt.Fprintf(os.Stdout, "\033[1;32mok\033[0m, Encrypting %s... ", fn)
                      if ciphertext, err := encrypt(plaintext, npassword, false, 0); err == nil {
                        fh.Truncate(int64(len(ciphertext)))
                        fh.WriteAt(ciphertext, 0)
                        fmt.Fprintf(os.Stdout, "\033[1;32mok\033[0m\n")
                      } else {
                        fmt.Fprintf(os.Stdout, "\033[1;31mfailed\033[0m\n")
                      }
                    } else {
                      fh.Truncate(int64(len(plaintext)))
                      fh.WriteAt(plaintext, 0)
                      fmt.Fprintf(os.Stdout, "\033[1;32mok\033[0m\n")
                      fh.Close()
  
                      if strings.HasSuffix(strings.ToLower(fn), ".vlt") {
                        if err := os.Rename(fn, fn[:len(fn) - 4]); err != nil {
                          fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
                        }
                      }
                    }
                  } else {
                    fmt.Fprintf(os.Stdout, "\033[1;31mfailed (invalid password or data not encrypted)\033[0m\n")
                  }
                }
              } else {
                fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
              }
            }
          } else {
            fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
          }
        }
      } else {
        if stdin, err := io.ReadAll(os.Stdin); err == nil {
          if mO == 16 {
            fmt.Fprintf(os.Stdout, "%x  -\n", sha256.Sum256(stdin))
          } else {
            if len(pukey) > 0 {
              if ciphertext, err := encryptX25519(stdin, pukey, true, 80); err == nil {
                fmt.Fprintf(os.Stdout, "%s\n", ciphertext)
              } else {
                fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Encrypt Data\033[0m\n")
              }
            } else {
              if password, _ := getPassword("Vaulty Password: "); len(password) > 0 {
                if mO == 1 {
                  if v, err := getPassword("Password Verification: "); password == v && err == nil {
                    fmt.Fprintf(os.Stderr, "\n")

                    if ciphertext, err := encrypt(stdin, password, true, 80); err == nil {
                      fmt.Fprintf(os.Stdout, "%s\n", ciphertext)
                    } else {
                      fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Encrypt Data\033[0m\n")
                    }
                  } else {
                    fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password Verification Failed\033[0m\n")
                  }
                } else if mO == 2 || mO == 4 {
                  if mO == 2 {
                    fmt.Fprintf(os.Stderr, "\n")
  
                    if len(prkey) > 0 {
                      var err error
                      if prkey, err = decrypt(prkey, password); err != nil {
                        fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Unable to Decrypt Key File\033[0m\n")
                        os.Exit(0)
                      }
                    }
                  }
  
                  var plaintext []byte
                  var err error
  
                  if len(prkey) > 0 {
                    plaintext, err = decryptX25519(stdin, prkey)
                  } else {
                    plaintext, err = decrypt(stdin, password)
                  }
  
                  if err == nil {
                    if mO == 4 {
                      if npassword, _ := getPassword("\nNew Vaulty Password: "); len(npassword) > 0 {
                        if v, err := getPassword("Password Verification: "); npassword == v && err == nil {
                          fmt.Fprintf(os.Stderr, "\n")
                          if ciphertext, err := encrypt(plaintext, npassword, true, 80); err == nil {
                            fmt.Fprintf(os.Stdout, "%s\n", ciphertext)
                          } else {
                            fmt.Fprintf(os.Stderr, "\033[1;31mError: Unable to Re-Encrypt Data\033[0m\n")
                          }
                        } else {
                          fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password Verification Failed\033[0m\n")
                        }
                      } else {
                        fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password is Mandatory\033[0m\n")
                      }
                    } else {
                      fmt.Fprintf(os.Stdout, "%s", plaintext)
                    }
                  } else {
                    fmt.Fprintf(os.Stderr, "\033[1;31mError: Invalid Password or Data Not Encrypted\033[0m\n")
                  }
                }
              } else {
                fmt.Fprintf(os.Stderr, "\n\033[1;31mError: Password is Mandatory\033[0m\n")
              }
            }
          }
        } else {
          fmt.Fprintf(os.Stderr, "\033[1;31merror: %v\033[0m\n", err)
        }
      }
    }
  } else {
    fmt.Fprintf(os.Stderr, "Vaulty %s - Encrypt/Decrypt with ChaCha20-Poly1305\n", Version)
    fmt.Fprintf(os.Stderr, "Copyright (c) 2021-2024 Chris Mason <chris@netnix.org>\n\n")
    fmt.Fprintf(os.Stderr, "Usage: vaulty keygen <keyfile>\n")
    fmt.Fprintf(os.Stderr, "              encrypt [-r <public id>] [files]\n")
    fmt.Fprintf(os.Stderr, "              decrypt [-k <keyfile>] [files]\n")
    fmt.Fprintf(os.Stderr, "              chpass [files]\n")
    fmt.Fprintf(os.Stderr, "              sha256 [files]\n")
  }
}

func smatch(a string, b string) bool {
  mlen := len(a)
  if len(b) < mlen {
    mlen = len(b)
  }
  return strings.ToLower(a) == strings.ToLower(b)[:mlen]
}

func getPassword(prompt string) (string, error) {
  if runtime.GOOS == "windows" {
    fmt.Fprintf(os.Stderr, "%s", prompt)
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    fmt.Fprintf(os.Stderr, "\n")
    return string(password), err

  } else {
    if tty, err := os.Open("/dev/tty"); err == nil {
      defer tty.Close()

      fmt.Fprintf(os.Stderr, "%s", prompt)
      password, err := term.ReadPassword(int(tty.Fd()))
      fmt.Fprintf(os.Stderr, "\n")
      return string(password), err

    } else {
      return "", err
    }
  }
}

func chunkString(s string, size int) string {
  if size > 0 {
    ss := make([]string, 0, (len(s) / size) + 1)
    for len(s) > 0 {
      if len(s) < size {
        size = len(s)
      }
      ss, s = append(ss, s[:size]), s[size:]
    }
    return strings.Join(ss, "\n")
  } else {
    return s
  }
}

func generateKeyPair() ([]byte, []byte, error) {
  private := make([]byte, curve25519.ScalarSize)
  if _, err := rand.Read(private); err == nil {
    if public, err := curve25519.X25519(private, curve25519.Basepoint); err == nil {
      return private, public, nil
    } else {
      return []byte{}, []byte{}, err
    }
  } else {
    return []byte{}, []byte{}, err
  }
}

func deriveKey(password []byte, salt []byte, gsalt bool) ([]byte, uint32, error) {
  var usageCount uint32

  cKey := fmt.Sprintf("%x:%x", password, salt)

  if key, ok := kCache[cKey]; ok {
    copy(salt, key[:len(salt)])
    usageCount = binary.BigEndian.Uint32(key[len(key) - 4:]) + 1
    binary.BigEndian.PutUint32(key[len(key) - 4:], usageCount)
    kCache[cKey] = key
    return key[len(salt):len(salt) + chacha20poly1305.KeySize], usageCount, nil
  }

  if gsalt {
    if _, err := rand.Read(salt); err != nil {
      return []byte{}, 0, err
    }
  }

  key, err := scrypt.Key(password, salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
  if err == nil {
    kCache[cKey] = append([]byte{}, salt...)
    kCache[cKey] = append(kCache[cKey], key...)
    kCache[cKey] = append(kCache[cKey], make([]byte, 4)...)
  }
  return key, usageCount, err
}

func stripArmour(ciphertext []byte) []byte {
  isASCII := true

  for i := 0; i < len(ciphertext); i++ {
    if ciphertext[i] > 127 {
      isASCII = false
      break
    }
  }

  if isASCII {
    ciphertext = bytes.TrimSpace(bytes.ReplaceAll(bytes.ReplaceAll(ciphertext, []byte("\r"), []byte{}), []byte("\n"), []byte{}))

    if bytes.HasPrefix(ciphertext, []byte(vaultyPrefix)) {
      var err error
      if ciphertext, err = base64.StdEncoding.DecodeString(string(ciphertext[len(vaultyPrefix):])); err != nil {
        panic(err)
      }
    }
  }
  return ciphertext
}

func encryptX25519(plaintext []byte, rpublic []byte, armour bool, cols int) ([]byte, error) {
  private := make([]byte, curve25519.ScalarSize)

  if _, err := rand.Read(private); err == nil {
    if public, err := curve25519.X25519(private, curve25519.Basepoint); err == nil {
      if shared, err := curve25519.X25519(private, rpublic); err == nil {
        salt := make([]byte, saltSize)

        if _, err := rand.Read(salt); err == nil {
          key := make([]byte, chacha20poly1305.KeySize)
          h := hkdf.New(sha256.New, shared, salt, []byte("vaulty/x25519"))

          if _, err := io.ReadFull(h, key); err == nil {
            if cipher, err := chacha20poly1305.New(key); err == nil {
              if cap(plaintext) < (len(plaintext) + x25519Overhead + chacha20poly1305.Overhead) {
                tmp := make([]byte, len(plaintext), len(plaintext) + x25519Overhead + chacha20poly1305.Overhead)
                copy(tmp, plaintext)
                plaintext = tmp
              }

              ciphertext := cipher.Seal(plaintext[:0], make([]byte, chacha20poly1305.NonceSize), plaintext, nil)
              ciphertext = ciphertext[:len(ciphertext) + x25519Overhead]

              copy(ciphertext[x25519Overhead:], ciphertext)
              copy(ciphertext[saltSize + 1:], public)
              copy(ciphertext[1:], salt)
              ciphertext[0] = 0xF1

              if armour {
                ciphertext = []byte(chunkString(vaultyPrefix + base64.StdEncoding.EncodeToString(ciphertext), cols))
              }
              return ciphertext, nil

            } else {
              return []byte{}, err
            }
          } else {
            return []byte{}, err
          }
        } else {
          return []byte{}, err
        }
      } else {
        return []byte{}, err
      }
    } else {
      return []byte{}, err
    }
  } else {
    return []byte{}, err
  }
}

func decryptX25519(ciphertext []byte, private []byte) ([]byte, error) {
  ciphertext = stripArmour(ciphertext)

  if (len(ciphertext) > x25519Overhead) && (ciphertext[0] == 0xF1) {
    if shared, err := curve25519.X25519(private, ciphertext[saltSize + 1:saltSize + curve25519.ScalarSize + 1]); err == nil {
      key := make([]byte, chacha20poly1305.KeySize)
      h := hkdf.New(sha256.New, shared, ciphertext[1:saltSize + 1], []byte("vaulty/x25519"))

      if _, err := io.ReadFull(h, key); err == nil {
        if cipher, err := chacha20poly1305.New(key); err == nil {
          ciphertext = ciphertext[x25519Overhead:]

          if plaintext, err := cipher.Open(ciphertext[:0], make([]byte, chacha20poly1305.NonceSize), ciphertext, nil); err == nil {
            return plaintext, nil

          } else {
            return []byte{}, err
          }
        } else {
          return []byte{}, err
        }
      } else {
        return []byte{}, err
      }
    } else {
      return []byte{}, err
    }
  }
  return []byte{}, errors.New("Invalid Vaulty Ciphertext")
}

func encrypt(plaintext []byte, password string, armour bool, cols int) ([]byte, error) {
  salt := make([]byte, saltSize)
  key, uc, err := deriveKey([]byte(password), salt, true)
  if err == nil {
    nonce := make([]byte, chacha20poly1305.NonceSize)
    if _, err := rand.Read(nonce); err == nil {
      binary.BigEndian.PutUint32(nonce[len(nonce) - 4:], uc)

      if cipher, err := chacha20poly1305.New(key); err == nil {
        if cap(plaintext) < (len(plaintext) + standardOverhead + chacha20poly1305.Overhead) {
          tmp := make([]byte, len(plaintext), len(plaintext) + standardOverhead + chacha20poly1305.Overhead)
          copy(tmp, plaintext)
          plaintext = tmp
        }

        ciphertext := cipher.Seal(plaintext[:0], nonce, plaintext, nil)
        ciphertext = ciphertext[:len(ciphertext) + standardOverhead]

        copy(ciphertext[standardOverhead:], ciphertext)
        copy(ciphertext[saltSize + 1:], nonce)
        copy(ciphertext[1:], salt)
        ciphertext[0] = 0x01

        if armour {
          ciphertext = []byte(chunkString(vaultyPrefix + base64.StdEncoding.EncodeToString(ciphertext), cols))
        }
        return ciphertext, nil

      } else {
        return []byte{}, err
      }
    } else {
      return []byte{}, err
    }
  }
  return []byte{}, err
}

func decrypt(ciphertext []byte, password string) ([]byte, error) {
  ciphertext = stripArmour(ciphertext)

  if (len(ciphertext) > standardOverhead) && (ciphertext[0] == 0x01) {
    if key, _, err := deriveKey([]byte(password), ciphertext[1:saltSize + 1], false); err == nil {
      if cipher, err := chacha20poly1305.New(key); err == nil {
        nonce := make([]byte, chacha20poly1305.NonceSize)
        copy(nonce, ciphertext[saltSize + 1:standardOverhead])
        ciphertext = ciphertext[standardOverhead:]

        if plaintext, err := cipher.Open(ciphertext[:0], nonce, ciphertext, nil); err == nil {
          return plaintext, nil

        } else {
          return []byte{}, err
        }
      } else {
        return []byte{}, err
      }
    } else {
      return []byte{}, err
    }
  }
  return []byte{}, errors.New("Invalid Vaulty Ciphertext")
}
