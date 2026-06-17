#include <stdio.h>
#include "quote.h"

#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

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
    TSS2_ABI_VERSION *CURRENT = NULL;
    ESYS_TR handle;



    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    if(rc != TSS2_RC_SUCCESS){
        printf("tctildr initialize failed\n");
        free(es_ctx);
        return 1;
    }
    printf("tctildr initialize success\n");

    rc = Esys_Initialize(&es_ctx, t_ctx, CURRENT);
    if(rc != TSS2_RC_SUCCESS){
        printf("esys initialize failed:0x%x\n",rc);
        free(t_ctx);
        free(es_ctx);
        return 1;
    }

    printf("Initialize success\n");

    rc = Esys_TR_FromTPMPublic(
        es_ctx,
        0x81010010,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &handle
    );

    TPM2B_DATA qualifyingData;
    qualifyingData.size = 20;
    TPM2B_DIGEST *nonce;

    rc = Esys_GetRandom(
            es_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            qualifyingData.size,
            &nonce
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("nonce OK\n");

    memcpy(qualifyingData.buffer, nonce->buffer, qualifyingData.size);

    TPML_DIGEST_VALUES ex_value;
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
            handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quote,
            &signature
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("quote OK\n");

    TPM2B_MAX_BUFFER data;
    data.size = quote->size;
    memcpy(data.buffer, quote->attestationData, quote->size);

    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    rc = Esys_Hash(
        es_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &data,
        TPM2_ALG_SHA256,
        //ESYS_TR_RH_OWNER,
        ESYS_TR_RH_NULL,
        &digest,
        &validation
    );
    rc_check(rc, t_ctx, es_ctx);
    printf("hash OK\n");

    TPMT_TK_VERIFIED *valid;

    rc = Esys_VerifySignature(
            es_ctx,
            handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            digest,
            signature,
            &valid
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("verify OK\n");

    return 0;
}
