from binascii import unhexlify, hexlify
from OpenSSL import crypto
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import base64
import hashlib
import logging
import traceback

from provider.models import Run, Job, App

import intel_sgx_ra
from intel_sgx_ra import attest
from intel_sgx_ra.quote import Quote

##################################################
######### ALERT -- MONKEY PATCH -- ALERT #########
##################################################
# monkey patching the get_pck_cert_crl call in the
# attest module to allow the `processor` mode of
# PCK CRL to be downloaded. The `intel_sgx_ra` 
# library at version 1.0.1 allows `processor` as a 
# function param in get_pck_cert_crl, but it 
# is not configurable/accessible

def patched_pcs_pck_crl_function(base_url, string):
    return intel_sgx_ra.pcs.get_pck_cert_crl(base_url, "processor")

attest.get_pck_cert_crl = patched_pcs_pck_crl_function
##################################################
######### ALERT -- MONKEY PATCH -- ALERT #########
##################################################

logger = logging.getLogger(__name__)
PCCS_URL = "https://pccs.mse.cosmian.com"

def sgx_check(body):
    b64_sgx_quote = body["context"]["sgxQuote"]
    b64_public_key = body["context"]["publicKey"]

    sgx_quote = ''
    public_key = ''

    try:
        sgx_quote = base64.b64decode(b64_sgx_quote)
        public_key = base64.b64decode(b64_public_key)
    except base64.binascii.Error:
        logger.error("Invalid SGX quote/public key - bad base64")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed!",
        }
        return JsonResponse(result, status=403)

    logger.debug("Got SGX quote and public key")
    try:
        attest.remote_attestation(sgx_quote, PCCS_URL)
        quote = Quote.from_bytes(sgx_quote)
        pkey_hash_in_quote = quote.report_body.report_data
        real_pkey_hash = hashlib.sha512()
        real_pkey_hash.update(public_key)

        if real_pkey_hash.digest() != pkey_hash_in_quote:
            logger.error("Hash in quote : " + hexlify(pkey_hash_in_quote).decode('ascii') 
                         + " hash of pkey : " + real_pkey_hash.hexdigest())
            result = {
                    "type": "urn:apd:Deny",
                    "title": "Failed!",
                    "detail": "Invalid SGX quote",
                    }
            return JsonResponse(result, status=403)

        logger.error("WARNING - No MRENCLAVE or hardware-specific validation")
        item_id = body["item"]["itemId"]

        running_jobs = (
            Run.objects.filter(status="R")
            .filter(job__resource_id=item_id)
            .filter(job__app__execution_platform=App.AppExecutionPlatforms.INTEL_SGX)
            #.filter(job__app__base_pcrs=pcrs_0_1_2)
        )

        if len(running_jobs) == 0:
            logger.error("Could not find job that matches item")
            result = {
                "type": "urn:apd:Deny",
                "title": "Failed!",
                "detail": "Failed!",
            }
            return JsonResponse(result, status=403)

    except Exception as e:
        logger.error("Caught error of type : " + type(e).__name__)
        logger.error(e)
        traceback.print_tb(e.__traceback__)

        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Invalid SGX quote",
        }
        return JsonResponse(result, status=403)

    result = {
        "type": "urn:apd:Allow",
        "apdConstraints": {"publicKey": b64_public_key}
    }
    return JsonResponse(result)
