#ifdef __cplusplus
#include "SealPIR/pir_client.hpp"
#include "SealPIR/pir_server.hpp"
#include <seal/seal.h>

using namespace std; 
using namespace seal;

struct Params {
    seal::EncryptionParameters *enc_params;
    PirParams *pir_params;
    uint64_t num_items;
    uint64_t item_bytes;
    uint64_t poly_degree;
    uint64_t logt;
    uint64_t d;
};

struct ServerWrapper {
    PIRServer *server; 
    Params *params;
};

struct ClientWrapper {
    PIRClient *client; 
    Params *params;
    uint64_t client_id;
};

struct SerializedAnswer {
    string str;
    uint64_t ciphertext_size;
    uint64_t count; 
};

struct SerializedQuery {
    string str;
    uint64_t client_id;
    uint64_t ciphertext_size;
    uint64_t count; 
};

struct SerializedGaloisKeys {
    string str;
    uint64_t client_id;
};
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
// Param gen 
extern void* init_params(uint64_t num_items, uint64_t item_bytes, uint64_t poly_degree, uint64_t logt, uint64_t d);

// Client functions 
extern void* init_client_wrapper(void *params, uint64_t client_id); 
extern void* gen_galois_keys(void *client_wrapper);
extern void* gen_query(void *client_wrapper, uint64_t desiredIndex);
extern char* recover(void *client_wrapper, void *serialized_answer);
extern uint64_t fv_index(void *client_wrapper, uint64_t index);
extern uint64_t fv_offset(void *client_wrapper, uint64_t index);

// Server functions 
extern void* init_server_wrapper(void *params); 
extern void set_galois_keys(void *server_wrapper, void *serialized_galois_keys);
extern void setup_database(void *server_wrapper, char* data);
extern void* gen_answer(void *server_wrapper, void *serialized_query);

// Memory management functions
extern void free_params(void *params);
extern void free_client_wrapper(void *client_wrapper);
extern void free_server_wrapper(void *server_wrapper);

#ifdef __cplusplus
}
#endif
