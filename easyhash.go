// Copyright (c) 2014, Floor Terra <floort@gmail.com>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
// OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

package easyhash

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const SaltLength = 42 // In bytes
const Seperator = ":"

func newSalt() (string, error) {
	b := make([]byte, SaltLength)
	n, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	if n != SaltLength {
		return "", errors.New("Could not read the expected amount of random bytes.")
	}
	str := base64.StdEncoding.EncodeToString(b)
	return str, nil
}

func hashSaltedPassword(password, salt string) (string, error) {
	saltbytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", err
	}
	if len(saltbytes) != SaltLength {
		return "", errors.New("Salt is not of the expected length")
	}
	hash, err := scrypt.Key([]byte(password), saltbytes, 16384, 8, 1, SaltLength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s%s", salt, Seperator, base64.StdEncoding.EncodeToString(hash)), nil
}

func HashPassword(password string) (string, error) {
	salt, err := newSalt()
	if err != nil {
		return "", err
	}
	return hashSaltedPassword(password, salt)
}

func CheckPassword(password, hash string) (bool, error) {
	split := strings.Split(hash, Seperator)
	if len(split) != 2 {
		return false, errors.New("Invalid password hash format.")
	}
	testhash, err := hashSaltedPassword(password, split[0])
	if err != nil {
		return false, err
	}
	if testhash == hash {
		return true, nil
	}
	return false, nil
}
