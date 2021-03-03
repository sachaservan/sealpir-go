package sealpir

import (
	"crypto/rand"
	"crypto/sha256"
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

	return InitParams(numItems, itemBytes, polyDegree, logt, d, 1)
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
	answers := server.GenAnswer(query)
	res := client.Recover(answers[0], offset)

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
}

func BenchmarkHash(b *testing.B) {
	var prev [32]byte
	for i := 0; i < b.N; i++ {
		prev = sha256.Sum256(prev[:])
	}
}

func Benchmark(b *testing.B) {
	// test parameters
	numItems := 1 << 20
	nParallel := 20
	itemBytes := 256
	polyDegree := 2048
	logt := 12
	d := 2

	params := InitParams(numItems, itemBytes, polyDegree, logt, d, nParallel)

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
	query := client.GenQuery(index)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		server.GenAnswer(query)
	}
}
