package libgosrp

func Pad(length int, src []byte) []byte {
	if len(src) > length {
		//error
	} else {
		dst := make([]byte, length)
		copy(dst[length-len(src):], src)
		return dst
	}
	return nil
}
