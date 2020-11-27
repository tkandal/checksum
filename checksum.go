package checksum

import (
	"bytes"
	"encoding/hex"
	"github.com/DataDog/mmh3"
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
	buf := bytes.NewBufferString(str)
	return mcs.SumBytes(buf.Bytes())
}

func (mcs *Murmur3CheckSum) SumBytes(b []byte) string {
	return hex.EncodeToString(mmh3.Hash128x64(b))
}
