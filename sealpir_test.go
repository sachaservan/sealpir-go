package sealpir

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func getTestParams() *Params {
	// test parameters
	numItems := 1 << 12
	itemBytes := 288
	polyDegree := 2048
	logt := 12
	d := 2

	return InitParams(numItems, itemBytes, polyDegree, logt, d)
}

func TestInitParams(t *testing.T) {
	getTestParams()
}

func TestInitClient(t *testing.T) {
	params := getTestParams()
	client := InitClient(params, 0)

	params.Free()
	client.Free()
}

func TestInitServer(t *testing.T) {
	params := getTestParams()
	server := InitServer(params)

	params.Free()
	server.Free()
}

func TestFull(t *testing.T) {

	// replicates SealPIR/main.cpp / SealPIR/main.c

	params := getTestParams()
	client := InitClient(params, 0)
	server := InitServer(params)

	keys := client.GenGaloisKeys()
	server.SetGaloisKeys(keys)

	data := make([]byte, params.ItemBytes*params.NumItems)
	rand.Read(data) // fill with random bytes

	db := &Database{
		bytes: data,
	}

	server.SetupDatabase(db)

	elemIndexBig, _ := rand.Int(rand.Reader, big.NewInt(int64(params.NumItems)))
	elemIndex := elemIndexBig.Int64() % int64(params.NumItems)

	index := client.GetFVIndex(elemIndex)
	offset := client.GetFVOffset(elemIndex)

	query := client.GenQuery(index)
	ans := server.GenAnswer(query)
	res := client.Recover(ans, offset)

	bytes := int64(params.ItemBytes)

	// check that we retrieved the correct element
	for i := int64(0); i < int64(params.ItemBytes); i++ {
		if res[(offset*bytes)+i] != db.bytes[(elemIndex*bytes)+i] {
			t.Fatalf("Main: elems %d, db %d\n",
				res[(offset*bytes)+i],
				db.bytes[(elemIndex*bytes)+i])
		}
	}

	client.Free()
	server.Free()
	params.Free()
	keys.Free()
}
