package chaincode

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"crypto/rand"
    "crypto/sha256"
    "math/big"
    "crypto/elliptic"
    // "encoding/binary"
    "strings"
	"strconv"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}


// InitLedger adds a base set of assets to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}


func (s *SmartContract) Add(ctx contractapi.TransactionContextInterface, i int, j int)int{
	return i+j;
}

func convert(b []byte) string {
	s := make([]string, len(b))
	for i := range b {
		s[i] = strconv.Itoa(int(b[i]))
	}

	return strings.Join(s, "")
}
func (TT *SmartContract) PartialPrivateKey(x1, y1, x2, y2 string) string {
	type Point struct {
		X, Y *big.Int
	}
	type Public struct {
		G    *elliptic.CurveParams
		P    *Point
		Ppub *Point
		q    *big.Int
		Ri   *Point
	}
	curve := elliptic.P256()
	q := curve.Params().N
	gx, gy := curve.Params().Gx, curve.Params().Gy
	P := &Point{X: gx, Y: gy}

	// s ← RandomSelect(160 bits)
	s, err := rand.Int(rand.Reader, q)
	if err != nil {
		return "Error"
	}
	// Ppub ← sP
	PpubX, PpubY := curve.ScalarMult(P.X, P.Y, s.Bytes())
	Ppub := &Point{X: PpubX, Y: PpubY}

	// Convert input strings to big integers
	x1 = strings.TrimSuffix(x1, "\n")
	y1 = strings.TrimSuffix(y1, "\n")
	PIDiX, a := new(big.Int).SetString(x1, 10)
	if !a {
		return "Invalid PID x coordinate!"
	}
	PIDiY, _ := new(big.Int).SetString(y1, 10)
	if !a {
		return "Invalid PID y coordinate!"
	}

	// Create a point using the user input
	PIDi := &Point{X: PIDiX, Y: PIDiY}

	// Convert input strings to big integers
	x2 = strings.TrimSuffix(x2, "\n")
	y2 = strings.TrimSuffix(y2, "\n")
	CIDiX, b := new(big.Int).SetString(x2, 10)
	if !b {
		return "Invalid CID x coordinate!"
	}
	CIDiY, b := new(big.Int).SetString(y2, 10)
	if !b {
		return "Invalid CID y coordinate!"
	}

	// Create a point using the user input
	CIDi := &Point{X: CIDiX, Y: CIDiY}
	//nBigInt, _ := new(big.Int).SetString(string(n), 10)

	//if CIDi.X.Cmp(nBigInt) < 0 {
	sPIDiX, sPIDiY := curve.ScalarMult(PIDi.X, PIDi.Y, s.Bytes())
	sPIDi := &Point{X: sPIDiX, Y: sPIDiY}
	sPIDineg := &Point{
		X: sPIDi.X,
		Y: new(big.Int).Neg(sPIDi.Y).Mod(sPIDi.Y, curve.Params().P),
	}
	IDiX, IDiY := curve.Add(CIDi.X, CIDi.Y, sPIDineg.X, sPIDineg.Y)
	IDi := &Point{X: IDiX, Y: IDiY}
	// Generate a random value ri and calculate Ri
	ri, err := rand.Int(rand.Reader, q)
	if err != nil {
		return "Error"
	}
	RiX, RiY := curve.ScalarBaseMult(ri.Bytes())
	Ri := &Point{X: RiX, Y: RiY}

	// Calculate αi
	idBytes := elliptic.Marshal(curve, IDi.X, IDi.Y)
	riBytes := elliptic.Marshal(curve, Ri.X, Ri.Y)
	data := append(Ppub.X.Bytes(), Ppub.Y.Bytes()...)
	// Concatenate Ppub, IDi, and Ri byte arrays
	data = append(data, append(idBytes, riBytes...)...)

	// Hash the concatenated byte array
	hash := sha256.Sum256(data)

	// Convert the first 32 bytes of the hash to a big.Int
	alphaBytes := hash[:32]
	alphai := new(big.Int).SetBytes(alphaBytes)
	/*
		fmt.Print("alpha = ")
		fmt.Println(alphai)
	*/
	// Calculate ppki and xppki
	xppki := make([]byte, 32)
	ppki := new(big.Int).Add(ri, new(big.Int).Mul(alphai, s))
	/*
		fmt.Print("ppk =       ")
		fmt.Println(ppki.Bytes())
	*/
	// idibytes := IDi.Marshal()
	idibytes := elliptic.Marshal(curve, IDi.X, IDi.Y)
	//fmt.Println("idibytes = ", idibytes)
	for i := 0; i < len(xppki); i++ {
		xppki[i] = ppki.Bytes()[i] ^ idibytes[i]
	}
	//fmt.Println("xppk = ", xppki)

	return convert(xppki)
}