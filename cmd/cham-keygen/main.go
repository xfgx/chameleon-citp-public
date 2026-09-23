package main

import (
	"fmt"

	"chameleon/internal/chameleon"
)

// cham-keygen — генерация пары ключей устройства/ноды.
// Приватный ключ хранится на устройстве, публичный — в белом списке ноды.
func main() {
	priv, pub, err := chameleon.GenerateNodeKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("private:", priv)
	fmt.Println("public: ", pub)
}
