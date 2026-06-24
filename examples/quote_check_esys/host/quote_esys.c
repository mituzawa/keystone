#include <stdio.h>
#include "quote.h"

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_mu.h>

static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
    if(esys){
        Esys_Finalize(&esys);
        free(esys);
    }
    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
        free(tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
    if(rc != TSS2_RC_SUCCESS){
        printf("Failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        ctx_finalize(tcti, esys);
        exit(1);
    }
}

int test_quote(QuoteResult *result){
    TSS2_RC rc;
    static ESYS_CONTEXT *es_ctx = NULL;
    static TSS2_TCTI_CONTEXT *t_ctx = NULL;

    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    if(rc != TSS2_RC_SUCCESS){
        printf("tctildr initialize failed\n");
        free(es_ctx);
        return 1;
    }
    printf("tctildr initialize success\n");

    rc = Esys_Initialize(&es_ctx, t_ctx, NULL);
    if(rc != TSS2_RC_SUCCESS){
        printf("esys initialize failed:0x%x\n",rc);
        return 1;
    }

    printf("Initialize success\n");

    TPM2B_DATA qualifyingData;
    qualifyingData.size = 32;
    TPM2B_DIGEST *nonce = {0};

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0},
            .data     = {.size = 0},
        }
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_RESTRICTED |
                TPMA_OBJECT_DECRYPT,
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits   = {.aes = 128},
                    .mode      = {.aes = TPM2_ALG_CFB}
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0},
        }
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    ESYS_TR primary_handle =ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *primary_Data = NULL;
    TPM2B_DIGEST *primary_Hash = NULL;
    TPMT_TK_CREATION *primary_Ticket = NULL;
    
    rc = Esys_CreatePrimary(
            es_ctx,
            ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inSensitive,
            &inPublic,
            &outsideInfo,
            &creationPCR,
            &primary_handle,
            &outPublic,
            &primary_Data,
            &primary_Hash,
            &primary_Ticket
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("Primary key created. Handle: 0x%x\n", primary_handle);

    TPM2B_PUBLIC ak_inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,

            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_SIGN_ENCRYPT |
                TPMA_OBJECT_RESTRICTED,

            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme = {
                    .scheme = TPM2_ALG_RSASSA,
                    .details.rsassa.hashAlg = TPM2_ALG_SHA256
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0},
        }
    };

    TPM2B_PUBLIC *ak_pub = NULL;
    TPM2B_PRIVATE *ak_priv = NULL;
    TPM2B_CREATION_DATA *ak_Data = NULL;
    TPM2B_DIGEST *ak_Hash = NULL;
    TPMT_TK_CREATION *ak_Ticket = NULL;

    rc = Esys_Create(
            es_ctx,
            primary_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inSensitive,
            &ak_inPublic,
            &outsideInfo,
            &creationPCR,
            &ak_priv,
            &ak_pub,
            &ak_Data,
            &ak_Hash,
            &ak_Ticket
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("create ak OK\n");

    TPM2_HANDLE load_handle = ESYS_TR_NONE;

    rc = Esys_Load(
            es_ctx,
            primary_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            ak_priv,
            ak_pub,
            &load_handle
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("load OK\n");
    
    uint8_t ak_pub_buf[1024];
    size_t ak_offset = 0;

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
            ak_pub,
            ak_pub_buf,
            sizeof(ak_pub_buf),
            &ak_offset
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("Marshal OK\n");
    printf("Marshal size = %zu\n", ak_offset);

    rc = Esys_GetRandom(
            es_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            qualifyingData.size,
            &nonce
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("nonce OK\n");

    memcpy(qualifyingData.buffer, nonce->buffer, qualifyingData.size);

    TPML_DIGEST_VALUES ex_value = {0};
    ex_value.count = 1;
    ex_value.digests -> hashAlg = TPM2_ALG_SHA256;
    memcpy(ex_value.digests -> digest.sha256, nonce->buffer, nonce->size);

    rc = Esys_PCR_Extend(
            es_ctx,
            ESYS_TR_PCR16,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &ex_value
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("extend OK\n");

    TPM2B_ATTEST *quote;
    TPMT_SIGNATURE *signature;

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    /*
    pcrSelect[0] →   PCR 0 ～ 7
    pcrSelect[1] →   PCR 8 ～ 15
    pcrSelect[2] →   PCR 16 ～ 23
    */
    TPML_PCR_SELECTION Select_PCR;
    Select_PCR.count = 1;
    Select_PCR.pcrSelections -> hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections -> sizeofSelect = 3;
    //Select_PCR.pcrSelections -> pcrSelect[0] = ;
    Select_PCR.pcrSelections -> pcrSelect[1] = 1 << 2;
    Select_PCR.pcrSelections -> pcrSelect[2] = 1;

    rc = Esys_Quote(
            es_ctx,
            load_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quote,
            &signature
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("quote OK\n");

    result->quote_size = quote->size;
    if(quote->size > sizeof(result->quote)) memcpy(result->quote, quote->attestationData, quote->size);

    result->sig_size = signature->signature.rsassa.sig.size;
    memcpy(result->signature, signature->signature.rsassa.sig.buffer, result->sig_size);

    result->ak_pub_size = ak_offset;
    memcpy(result->ak_pub, ak_pub_buf, ak_offset);
    
    printf("HOST quote[0]=%u\n", result->ak_pub[0]);
    printf("HOST quote[1]=%u\n", result->ak_pub[1]);
    printf("HOST quote[2]=%u\n", result->ak_pub[2]);

    Esys_Free(outPublic);
    Esys_Free(primary_Data);
    Esys_Free(primary_Hash);
    Esys_Free(primary_Ticket);
    Esys_Free(ak_priv);
    Esys_Free(ak_pub);
    Esys_Free(ak_Data);
    Esys_Free(ak_Hash);
    Esys_Free(ak_Ticket);

    Esys_FlushContext(es_ctx, load_handle);
    Esys_FlushContext(es_ctx, primary_handle);

    ctx_finalize(t_ctx, es_ctx);
    return 0;
}
