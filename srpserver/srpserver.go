package srpserver

type Verifier struct {
    salt int
    key int
}

func CreateVerifier() Verifier {
    return Verifier{0, 0}
}

func TestVerifier() {

}