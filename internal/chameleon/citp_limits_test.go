package chameleon

import (
	"testing"
)

// TestCITPObjectOversizeLimit проверяет, что декодер CITP-объектов отклоняет
// попытки передать payload, превышающий допустимый предел maxCITPPayloadLen (65535 байт).
func TestCITPObjectOversizeLimit(t *testing.T) {
	obj := &CITPObject{
		ObjectID: 1,
		StreamID: 1,
		Payload:  make([]byte, 70000), // превышает uint16 / max buffer
	}
	enc := obj.Encode()
	if enc != nil {
		t.Fatalf("Encode должен возвращать nil для payload > 65535 байт")
	}
}

func TestDecodeCITPObjectTruncatedOrNil(t *testing.T) {
	_, err := DecodeCITPObject(nil)
	if err == nil {
		t.Fatal("nil буфер должен возвращать ошибку")
	}

	short := make([]byte, 30)
	_, err = DecodeCITPObject(short)
	if err == nil {
		t.Fatal("короткий заголовок (< 50 байт) должен возвращать ошибку")
	}
}
