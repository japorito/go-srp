package srpserver

import (
    "fmt"
    "testing"
)

func TestCreateVerifier(t *testing.T) {
    v, err := CreateVerifier("password", 128)
    if err != nil {
       fmt.Printf("Verifier is %v.\n\nSalt is %v.\n", v.V, v.S)
    } else {
       fmt.Println("Error: ", err)
    }
}