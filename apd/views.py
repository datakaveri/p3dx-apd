from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging
import json

from .platforms.nitro_attestation import nitro_check
from .platforms.sgx_attestation import sgx_check
from .platforms.maa_azure_amd_sev_attestation import maa_azure_amd_sev_check
from .platforms.non_maa_amd_sev_attestation import non_maa_amd_sev_check

logger = logging.getLogger(__name__)

@csrf_exempt
def show_userclasses(request):
    data = {"one": 1, "two": 2}
    return JsonResponse(data)

@csrf_exempt
def verify_enclave_call(request):
    body = json.loads(request.body.decode("utf-8"))

    if "context" not in body:
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Missing context",
        }
        return JsonResponse(result, status=403)

    context = body['context']

    if "attestationDocument" in context:
        return nitro_check(body)
    elif "sgxQuote" and "publicKey" in context:
        return sgx_check(body)
    elif "jwtMAA" in context:
        return maa_azure_amd_sev_check(body)
    elif "guest_report.bin" in context:
        return non_maa_amd_sev_check(body)
    else:
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Invalid context object for enclave APD. Must have `attestationDocument` or `sgxQuote`+`publicKey`",
        }
        return JsonResponse(result, status=403)
