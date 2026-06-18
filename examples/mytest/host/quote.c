#include <stdio.h>
#include <string.h>
#include "quote.h"

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_mu.h>

static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
    if(sys){
        Tss2_Sys_Finalize(sys);
        free(sys);
    }

    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
        free(tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
    if(rc != TSS2_RC_SUCCESS){
        printf("%s\n", Tss2_RC_Decode(rc));
            ctx_finalize(tcti, sys);
            exit(1);
    }
}

static void save_signature(TPMT_SIGNATURE *sig, const char *path){
    FILE *fp = fopen(path, "wb");
    if(!fp){
        perror("fopen");
        exit(1);
    }

    size_t written = fwrite(sig->signature.rsassa.sig.buffer, 1, sig->signature.rsassa.sig.size, fp);
    fclose(fp);

    if(written != sig->signature.rsassa.sig.size){
        fprintf(stderr, "failed to write signature file\n");
        exit(1);
    }
}

static void save_quote(TPM2B_ATTEST *quote, const char *path){
    FILE *fp = fopen(path, "wb");
    if(!fp){
        perror("fopen");
        exit(1);
    }

    size_t size = fwrite(quote->attestationData, 1, quote->size, fp);
    fclose(fp);

    if(size != quote->size){
        fprintf(stderr, "failed to write\n");
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
    CmdAuth.auths -> sessionHandle = TPM2_RS_PW;

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

    TPM2_HANDLE load_handle;
    TPM2B_NAME load_name;

    uint8_t ak_pub_buf[1024];
    size_t ak_offset;

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
    qualifyingData.size = 20;
    TPM2B_DIGEST nonce;

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

    TPM2B_ATTEST quote;
    TPMT_SIGNATURE signature = {0};

    TPML_PCR_SELECTION Select_PCR;
    Select_PCR.count = 1;
    Select_PCR.pcrSelections -> hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections -> sizeofSelect = 3;

    Select_PCR.pcrSelections -> pcrSelect[0] = 0;           //0~7
    Select_PCR.pcrSelections -> pcrSelect[1] = 1 << 2;      //8~15
    Select_PCR.pcrSelections -> pcrSelect[2] = 1;           //16~23

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

    save_signature(&signature, "sig.bin");
    printf("signature save OK\n");

    save_quote(&quote, "quote.bin");
    printf("quote save OK\n");

    TSS2L_SYS_AUTH_COMMAND CmdAuth_quote = {0};
    CmdAuth_quote.count = 1;
    CmdAuth_quote.auths -> sessionHandle = TPM2_RS_PW;

    TPML_DIGEST_VALUES value;
    value.count = 1;
    value.digests -> hashAlg = TPM2_ALG_SHA256;
    memcpy(value.digests -> digest.sha256, quote.attestationData, quote.size);

    rc = Tss2_Sys_PCR_Extend(
            s_ctx,
            16,
            &CmdAuth_quote,
            &value,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("Extend OK\n");

    ctx_finalize(t_ctx, s_ctx);
    return 0;
}
