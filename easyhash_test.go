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
	"testing"
)

func TestNewSalt(t *testing.T) {
	_, err := newSalt()
	if err != nil {
		t.Error(err)
	}
}

func TestHashPassword(t *testing.T) {
	p, err := HashPassword("password")
	if err != nil {
		t.Error(err)
	}
	ok, err := CheckPassword("password", p)
	if err != nil {
		t.Error(err)
	}
	if ok == false {
		t.Error("ffsfds")
	}
}
