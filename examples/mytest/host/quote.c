#include <stdio.h>
#include <string.h>
#include "quote.h"

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>

static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
    if(sys){
        Tss2_Sys_Finalize(sys);
        free(sys);
    }
    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
    if(rc != TSS2_RC_SUCCESS){
        printf("%s\n", Tss2_RC_Decode(rc));
            ctx_finalize(tcti, sys);
            exit(1);
    }
}

int test_quote(QuoteResult *result){
    TSS2_RC rc;
    size_t size;
    static TSS2_SYS_CONTEXT *s_ctx;
    static TSS2_TCTI_CONTEXT *t_ctx;
    TSS2_ABI_VERSION *CURRENT = NULL;

    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    rc_check(rc, t_ctx, s_ctx);
    printf("tcti Initialize OK\n");

    size = Tss2_Sys_GetContextSize(0);
    s_ctx = (TSS2_SYS_CONTEXT*)calloc(1, size);

    rc = Tss2_Sys_Initialize(s_ctx, size, t_ctx, CURRENT);
    rc_check(rc, t_ctx, s_ctx);
    printf("sapi Initialize OK\n");

    TSS2L_SYS_AUTH_COMMAND CmdAuth = {0};
    CmdAuth.count = 1;
    CmdAuth.auths[0].sessionHandle = TPM2_RS_PW;

    TSS2L_SYS_AUTH_RESPONSE rspAuth = {0};

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

    TPM2_HANDLE primary_handle;
    TPM2B_PUBLIC outPublic = {0};
    TPM2B_CREATION_DATA Data = {0};
    TPM2B_DIGEST Hash = {0};
    TPMT_TK_CREATION Ticket = {0};
    TPM2B_NAME primary_name = {0};

    rc = Tss2_Sys_CreatePrimary(
            s_ctx,
            TPM2_RH_OWNER,
            &CmdAuth,
            &inSensitive,
            &inPublic,
            &outsideInfo,
            &creationPCR,
            &primary_handle,
            &outPublic,
            &Data,
            &Hash,
            &Ticket,
            &primary_name,
            &rspAuth
            );

    rc_check(rc, t_ctx, s_ctx);
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
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                },
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

    TPM2B_PUBLIC ak_pub = {0};
    TPM2B_PRIVATE ak_priv = {0};
    TPM2B_CREATION_DATA ak_Data = {0};
    TPM2B_DIGEST ak_Hash = {0};
    TPMT_TK_CREATION ak_Ticket = {0};

    rc = Tss2_Sys_Create(
            s_ctx,
            primary_handle,
            &CmdAuth,
            &inSensitive,
            &ak_inPublic,
            &outsideInfo,
            &creationPCR,
            &ak_priv,
            &ak_pub,
            &ak_Data,
            &ak_Hash,
            &ak_Ticket,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("create ak OK\n");

    uint8_t ak_pub_buf[1024];
    size_t ak_offset = 0;

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
            &ak_pub,
            ak_pub_buf,
            sizeof(ak_pub_buf),
            &ak_offset
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("Murshal OK\n");
    printf("Marshal size = %zu\n", ak_offset);

    TPM2_HANDLE ak_handle;
    TPM2B_NAME ak_name;

    rc = Tss2_Sys_Load(
            s_ctx,
            primary_handle,
            &CmdAuth,
            &ak_priv,
            &ak_pub,
            &ak_handle,
            &ak_name,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("load OK\n");
/*
    TSS2L_SYS_AUTH_COMMAND CmdAuth = {0};
    CmdAuth.count = 1;
    CmdAuth.auths -> sessionHandle = TPM2_RS_PW;
*/
    TPMT_SIG_SCHEME scheme;
    scheme.scheme = TPM2_ALG_RSASSA;
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    //TSS2L_SYS_AUTH_RESPONSE rspAuth = {0};
    TPM2B_DATA qualifyingData;
    qualifyingData.size = 32;
    TPM2B_DIGEST nonce = {0};

    rc = Tss2_Sys_GetRandom(
            s_ctx,
            NULL,
            qualifyingData.size,
            &nonce,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("nonce OK\n");
    
    memcpy(qualifyingData.buffer, nonce.buffer, qualifyingData.size);

    TPM2B_ATTEST quote = {0};
    TPMT_SIGNATURE signature = {0};

    TPML_PCR_SELECTION Select_PCR = {0};
    Select_PCR.count = 1;
    Select_PCR.pcrSelections[0].hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections[0].sizeofSelect = 3;

    Select_PCR.pcrSelections[0].pcrSelect[0] = 0;           //0~7
    Select_PCR.pcrSelections[0].pcrSelect[1] = 1 << 2;      //8~15
    Select_PCR.pcrSelections[0].pcrSelect[2] = 1;           //16~23

    rc = Tss2_Sys_Quote(
            s_ctx,
            ak_handle,
            &CmdAuth,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quote,
            &signature,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("quote OK\n");

    result->quote_size = quote.size;
    if(quote.size > sizeof(result->quote)) memcpy(result->quote, quote.attestationData, quote.size);

    result->sig_size = signature.signature.rsassa.sig.size;
    memcpy(result->signature, signature.signature.rsassa.sig.buffer, result->sig_size);

    result->ak_pub_size = ak_offset;
    memcpy(result->ak_pub, ak_pub_buf, ak_offset);
/*
    printf("HOST quote[0]=%u\n", result->quote[0]);
    printf("HOST quote[1]=%u\n", result->quote[1]);
    printf("HOST quote[2]=%u\n", result->quote[2]);
    printf("HOST quote[3]=%u\n", (unsigned)result->quote[3]);
    printf("HOST quote[4]=%u\n", (unsigned)result->quote[4]);
    printf("HOST quote[5]=%u\n", (unsigned)result->quote[5]);

*/
    Tss2_Sys_FlushContext(s_ctx, ak_handle);
    Tss2_Sys_FlushContext(s_ctx, primary_handle);

    ctx_finalize(t_ctx, s_ctx);
    return 0;
}
