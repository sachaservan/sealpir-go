#include "wrapper.h"
#include <seal/seal.h>

using namespace std;
using namespace seal;

void* init_params(uint64_t num_items, uint64_t item_bytes, uint64_t poly_degree, uint64_t logt, uint64_t d) {

    EncryptionParameters *enc_params = new EncryptionParameters(scheme_type::BFV);
    PirParams *pir_params = new PirParams();
    gen_params(num_items, item_bytes, poly_degree, logt, d, *enc_params, *pir_params);
   
    struct Params *params = new Params(); 
    params->enc_params = enc_params;
    params->pir_params = pir_params;
    params->num_items = num_items;
    params->item_bytes = item_bytes;
    params->poly_degree = poly_degree;
    params->logt = logt;
    params->d = d;

    return params;
}

void* init_client_wrapper(void *params, uint64_t client_id) { 
    struct ClientWrapper *cw = new ClientWrapper();
    struct Params *p = (struct Params *)params;
    PIRClient *cli = new PIRClient(*(p->enc_params), *(p->pir_params));
    cw->client = cli;
    cw->params = p;
    cw->client_id = client_id;
    return cw;
}

void* gen_galois_keys(void *client_wrapper) {
    struct ClientWrapper *cw = (struct ClientWrapper *)client_wrapper;
    SerializedGaloisKeys *ser = new SerializedGaloisKeys();
    GaloisKeys galois_keys = cw->client->generate_galois_keys();
    string ser_keys = serialize_galoiskeys(galois_keys);
    ser->str = ser_keys.c_str();
    ser->str_len = ser_keys.length();
    ser->client_id = cw->client_id;
    return ser;
}

uint64_t fv_index(void *client_wrapper, uint64_t elem_index) {
    struct ClientWrapper *cw = (struct ClientWrapper *)client_wrapper;
    uint64_t size_per_item = cw->params->item_bytes;
    // index of FV plaintext
    uint64_t index = cw->client->get_fv_index(elem_index, size_per_item);

    return index; 
}

uint64_t fv_offset(void *client_wrapper, uint64_t elem_index) {
    struct ClientWrapper *cw = (struct ClientWrapper *)client_wrapper;
    uint64_t size_per_item = cw->params->item_bytes;
    // index of FV plaintext
    uint64_t index = cw->client->get_fv_index(elem_index, size_per_item);
    // offset in FV plaintext   
    uint64_t offset = cw->client->get_fv_offset(elem_index, size_per_item);

    return offset; 
}

void* gen_query(void *client_wrapper, uint64_t desiredIndex) {
    struct ClientWrapper *cw = (struct ClientWrapper *)client_wrapper;
    PirQuery query = cw->client->generate_query(desiredIndex);
    string query_ser = serialize_query(query);
    
    std::vector<seal::Ciphertext> size_test;
    size_test.push_back(query[0][0]);

    SerializedQuery *ser = new SerializedQuery();
    ser->str = query_ser.c_str();
    ser->str_len = query_ser.length();
    ser->ciphertext_size = serialize_ciphertexts(size_test).size();
    ser->count = 1;

    return ser;
}

char* recover(void *client_wrapper, void *serialized_answer) {
    struct ClientWrapper *cw = (struct ClientWrapper *)client_wrapper;
    struct SerializedAnswer *sa = (struct SerializedAnswer *)serialized_answer;

    string str(sa->str, sa->str_len);
    PirReply answer = deserialize_ciphertexts(sa->count, str, sa->ciphertext_size);
    Plaintext result = cw->client->decode_reply(answer);
    uint64_t size = ((cw->params->poly_degree * cw->params->logt) / 8);
    uint8_t* elems = new uint8_t[size]; 
    coeffs_to_bytes(cw->params->logt, result, elems, size);
    return (char*) elems; 
}


void* init_server_wrapper(void *params) {
    struct ServerWrapper *sw = new ServerWrapper();
    struct Params *p = (struct Params *)params;
    PIRServer *server = new PIRServer(*(p->enc_params), *(p->pir_params));
    sw->server = server;
    sw->params = p;
    return sw;
}

void set_galois_keys(void *server_wrapper, void *serialized_galois_keys) {
    struct ServerWrapper *sw = (ServerWrapper *)server_wrapper;
    struct SerializedGaloisKeys *k = (struct SerializedGaloisKeys *) serialized_galois_keys;
    string str(k->str, k->str_len);
    GaloisKeys *galois_keys = deserialize_galoiskeys(str);
    sw->server->set_galois_key(k->client_id, *galois_keys);
}

void setup_database(void *server_wrapper, char* data) {
    struct ServerWrapper *sw = (ServerWrapper *)server_wrapper;
    uint64_t size = sw->params->num_items * sw->params->item_bytes;
    auto db(make_unique<uint8_t[]>(size));
    memcpy(db.get(), data, size);
    sw->server->set_database(move(db), sw->params->num_items, sw->params->item_bytes);
    sw->server->preprocess_database();
}

void* gen_answer(void *server_wrapper, void *serialized_query) {
    struct ServerWrapper *sw = (ServerWrapper *)server_wrapper;
    struct SerializedQuery *sq = (SerializedQuery *)serialized_query;

    string str(sq->str, sq->str_len);
    PirQuery query = deserialize_query(
        sw->params->d, 
        sq->count, 
        str, 
        sq->ciphertext_size
    );

    PirReply res = sw->server->generate_reply(query, sq->client_id);
    string ser_ans = serialize_ciphertexts(res);

    std::vector<seal::Ciphertext> size_test;
    size_test.push_back(res[0]);

    SerializedAnswer *ans = new SerializedAnswer();
    ans->str = ser_ans.c_str();
    ans->str_len = ser_ans.length();
    ans->ciphertext_size = serialize_ciphertexts(size_test).size();
    ans->count = res.size();

     return ans;
}

void free_params(void *params) {
    struct Params *p = (struct Params *)params;
    free(p->pir_params);
    free(p->enc_params);
    free(p);
}

void free_client_wrapper(void *client_wrapper) {
    struct ClientWrapper *cw = (struct ClientWrapper *)client_wrapper;
    free(cw->client);
    free(cw);
}

void free_server_wrapper(void *server_wrapper) {
    struct ServerWrapper *sw = (ServerWrapper *)server_wrapper;
    free(sw->server);
    free(sw);
}