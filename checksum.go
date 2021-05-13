package checksum

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/DataDog/mmh3"
	"hash"
)

/*
 * Copyright (c) 2019, 2020 Norwegian University of Science and Technology
 */

// CheckSum implements some kind of checksum given a slice of bytes or string
type CheckSum interface {
	SumString(str string) string
	SumBytes(b []byte) string
}

type Murmur3CheckSum struct {
}

func (mcs *Murmur3CheckSum) SumString(str string) string {
	return mcs.SumBytes([]byte(str))
}

func (mcs *Murmur3CheckSum) SumBytes(b []byte) string {
	return hex.EncodeToString(mmh3.Hash128x64(b))
}

type SHA256CheckSum struct {
	hasher hash.Hash
}

func (h *SHA256CheckSum) SumString(str string) string {
	return h.SumBytes([]byte(str))
}

func (h *SHA256CheckSum) SumBytes(b []byte) string {
	hasher := h.getHasher()
	// hash.Write never returns an error, (int, error) is just to satisfy writer interface
	_, _ = hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (h *SHA256CheckSum) getHasher() hash.Hash {
	if h.hasher == nil {
		h.hasher = sha256.New()
	}
	return h.hasher
}
