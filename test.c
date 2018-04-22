#include <assert.h>
#include <string.h>

#include "aes.h"
#include "common.h"


void test_encrypt_mesh(void) {
#define PLAIN_TEXT_LEN 2
#define MAC_LENGH 4
#define AAD_LENGTH 1
    char *nonce_str = "00000000800000000000000000";
    uint8_t nonce[13] = {0};
    string2digit_no_reverse(nonce_str, nonce);
    mesh_print_array("nonce= ", nonce, 13);

    // sample data session key:
    char *sk_str = "00000000000000000000000000000000";
    uint8_t sk[16] = {0};
    string2digit_no_reverse(sk_str, sk);
    mesh_print_array("sk= ", sk, 16);

    // sample data message

    char *pbuf_str = "0213";
    uint8_t plain_len = strlen(pbuf_str)/2;
    uint8_t pbuf[32] = {0};
    string2digit_no_reverse(pbuf_str, pbuf);
    mesh_print_array("pbuf= ", pbuf, plain_len);

    // sample data MAC
    uint8_t adata[16] = {i};
    //uint8_t adata[16] = {0x03};
    uint8_t out[32];
    uint8_t auth_out[MAC_LENGH] = { 0x00};

    MESH_DEBUG("%s, start", __func__);
    int r = aes_ccm_ae(sk, 16, nonce,
                   MAC_LENGH, pbuf, plain_len,
                   adata, AAD_LENGTH, out, auth_out);
    MESH_DEBUG("r=%d", r);
    mesh_print_array("out= ", out, plain_len);
    mesh_print_array("auth_out: ", auth_out, MAC_LENGH);
}


int main(void) {
    test_encrypt_mesh();
    return 0;
}
