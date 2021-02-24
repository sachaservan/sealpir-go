package sealpir

// #cgo CFLAGS: -I"/usr/local/include"
// #cgo LDFLAGS: -lseal SealPIR/libsealwrapper.a -lstdc++
// #include <stdlib.h>
// #include "SealPIR/wrapper.h"
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
	Pointer unsafe.Pointer
}

type Database struct {
	bytes []byte
}

type Query struct {
	Pointer unsafe.Pointer
}

type Answer struct {
	Pointer unsafe.Pointer
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

	return &GaloisKeys{
		Pointer: C.gen_galois_keys(client.Pointer),
	}
}

func (server *Server) SetGaloisKeys(keys *GaloisKeys) {
	C.set_galois_keys(server.Pointer, keys.Pointer)
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
	return &Query{
		Pointer: C.gen_query(client.Pointer, C.ulonglong(index)),
	}
}

func (server *Server) GenAnswer(query *Query) *Answer {
	return &Answer{
		Pointer: C.gen_answer(server.Pointer, query.Pointer),
	}
}

func (client *Client) Recover(answer *Answer, offset int64) []byte {
	res := C.recover(client.Pointer, answer.Pointer)
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

func (keys *GaloisKeys) Free() {
	C.free(keys.Pointer)
}
