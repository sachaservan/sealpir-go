package sealpir

// #cgo CFLAGS: -I"/usr/local/include"
// #cgo LDFLAGS: -lseal C/libsealwrapper.a -lstdc++
// #include <stdlib.h>
// #include "C/wrapper.h"
import "C"
import (
	"unsafe"
)

type Params struct {
	Pointer   unsafe.Pointer
	NumItems  int
	ItemBytes int
}

type Client struct {
	Params  *Params
	Pointer unsafe.Pointer
}

type Server struct {
	Pointer unsafe.Pointer
}

type GaloisKeys struct {
	Str      string
	ClientID uint64
}

type Database struct {
	bytes []byte
}

type Query struct {
	Str            string
	ClientID       uint64
	CiphertextSize uint64
	Count          uint64
}

type Answer struct {
	Str            string
	ClientID       uint64
	CiphertextSize uint64
	Count          uint64
}

// QueryCStruct must match struct in wrapper.h *exactly*
type QueryCStruct struct {
	StrPtr         *C.char
	StrLen         C.ulonglong
	ClientID       C.ulonglong
	CiphertextSize C.ulonglong
	Count          C.ulonglong
}

// AnswerCStruct must match struct in wrapper.h *exactly*
type AnswerCStruct struct {
	StrPtr         *C.char
	StrLen         C.ulonglong
	CiphertextSize C.ulonglong
	Count          C.ulonglong
}

// GaloisKeysCStruct must match struct in wrapper.h *exactly*
type GaloisKeysCStruct struct {
	StrPtr   *C.char
	StrLen   C.ulonglong
	ClientID C.ulonglong
}

func InitParams(numItems, itemBytes, polyDegree, logt, d int) *Params {
	return &Params{
		NumItems:  numItems,
		ItemBytes: itemBytes,
		Pointer:   C.init_params(C.ulonglong(numItems), C.ulonglong(itemBytes), C.ulonglong(polyDegree), C.ulonglong(logt), C.ulonglong(d)),
	}
}

func InitClient(params *Params, clientId int) *Client {

	return &Client{
		Params:  params,
		Pointer: C.init_client_wrapper(params.Pointer, C.ulonglong(clientId)),
	}
}

func InitServer(params *Params) *Server {

	return &Server{
		Pointer: C.init_server_wrapper(params.Pointer),
	}
}

func (client *Client) GenGaloisKeys() *GaloisKeys {

	// HACK: convert SerializedGaloisKeys struct from wrapper.h into a GaloisKeys struct
	// see: https://stackoverflow.com/questions/28551043/golang-cast-memory-to-struct
	keyPtr := C.gen_galois_keys(client.Pointer)
	size := unsafe.Sizeof(GaloisKeysCStruct{})
	structMem := (*(*[1<<31 - 1]byte)(keyPtr))[:size]
	keyC := (*(*GaloisKeysCStruct)(unsafe.Pointer(&structMem[0])))

	key := GaloisKeys{
		Str: C.GoStringN(keyC.StrPtr, C.int(keyC.StrLen)),
	}
	key.ClientID = uint64(keyC.ClientID)

	return &key
}

func (server *Server) SetGaloisKeys(keys *GaloisKeys) {

	galKeysC := GaloisKeysCStruct{
		StrPtr: C.CString(keys.Str),
	}
	galKeysC.StrLen = C.ulonglong(len(keys.Str))
	galKeysC.ClientID = C.ulonglong(keys.ClientID)

	keysPtr := unsafe.Pointer(&galKeysC)

	C.set_galois_keys(server.Pointer, keysPtr)
}

func (server *Server) SetupDatabase(db *Database) {
	C.setup_database(server.Pointer, C.CString(string(db.bytes)))
}

func (client *Client) GetFVIndex(elemIndex int64) int64 {
	return int64(C.fv_index(client.Pointer, C.ulonglong(elemIndex)))
}

func (client *Client) GetFVOffset(elemIndex int64) int64 {
	return int64(C.fv_offset(client.Pointer, C.ulonglong(elemIndex)))
}

func (client *Client) GenQuery(index int64) *Query {

	// HACK: convert SerializedQuery struct from wrapper.h into a Query struct
	// see: https://stackoverflow.com/questions/28551043/golang-cast-memory-to-struct
	qPtr := C.gen_query(client.Pointer, C.ulonglong(index))
	size := unsafe.Sizeof(QueryCStruct{})
	structMem := (*(*[1<<31 - 1]byte)(qPtr))[:size]
	queryC := (*(*QueryCStruct)(unsafe.Pointer(&structMem[0])))

	query := Query{
		Str: C.GoStringN(queryC.StrPtr, C.int(queryC.StrLen)),
	}

	query.CiphertextSize = uint64(queryC.CiphertextSize)
	query.Count = uint64(queryC.Count)
	query.ClientID = uint64(queryC.ClientID)

	return &query
}

func (server *Server) GenAnswer(query *Query) *Answer {

	// convert to queryC type
	queryC := QueryCStruct{
		StrPtr: C.CString(query.Str),
	}
	queryC.CiphertextSize = C.ulonglong(query.CiphertextSize)
	queryC.StrLen = C.ulonglong(len(query.Str))
	queryC.Count = C.ulonglong(query.Count)
	queryC.ClientID = C.ulonglong(query.ClientID)

	qPtr := unsafe.Pointer(&queryC)
	ansPtr := C.gen_answer(server.Pointer, qPtr)

	// HACK: convert SerializedAnswer struct from wrapper.h into a Answer struct
	// see: https://stackoverflow.com/questions/28551043/golang-cast-memory-to-struct
	size := unsafe.Sizeof(AnswerCStruct{})
	structMem := (*(*[1<<31 - 1]byte)(ansPtr))[:size]
	answerC := (*(*AnswerCStruct)(unsafe.Pointer(&structMem[0])))

	answer := Answer{
		Str: C.GoStringN(answerC.StrPtr, C.int(answerC.StrLen)),
	}

	answer.CiphertextSize = uint64(answerC.CiphertextSize)
	answer.Count = uint64(answerC.Count)

	return &answer
}

func (client *Client) Recover(answer *Answer, offset int64) []byte {

	// convert to answerC type
	answerC := AnswerCStruct{
		StrPtr: C.CString(answer.Str),
	}
	answerC.CiphertextSize = C.ulonglong(answer.CiphertextSize)
	answerC.StrLen = C.ulonglong(len(answer.Str))
	answerC.Count = C.ulonglong(answer.Count)

	res := C.recover(client.Pointer, unsafe.Pointer(&answerC))
	minSize := 8 * (offset + 1) * int64(client.Params.ItemBytes)
	return C.GoBytes(unsafe.Pointer(res), C.int(minSize))
}

func (params *Params) Free() {
	C.free_params(params.Pointer)
}

func (client *Client) Free() {
	C.free_client_wrapper(client.Pointer)
}

func (server *Server) Free() {
	C.free_server_wrapper(server.Pointer)
}
