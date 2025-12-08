from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import base64
import json
import logging

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

logger = logging.getLogger(__name__)

HARDCODED_VM_CONFIG = {
    "console-enabled": True,
    "secure-boot": True,
    "tpm-enabled": True,
    "vmUniqueId": "DB5AAE36-AA94-43E4-BB97-7AC66937EE37",
}

HARDCODED_PCR_15 = "0x5EF15FCA5C2AF14EEF362ABA933A291F0269CB0D6ADE6111CB4766BFD10D767D"


def maa_azure_amd_sev_check(body):
    jwt_maa_in_context = body["context"]["jwtMAA"]

    decoded_jwt_maa = ""

    try:
        # Get the UNVERIFIED header from the JWT and get the `jku` field - which contains the JWKS URL
        unverified_header = jwt.get_unverified_header(jwt_maa_in_context)

        # Access the JWT public key from the URL
        jwks_url = unverified_header["jku"]
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(jwt_maa_in_context)

        # Verify and decode the JWT
        decoded_jwt_maa = jwt.decode(
            jwt_maa_in_context,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_signature": True},
        )

        if decoded_jwt_maa:
            logger.debug("Decoded JWT MAA successfully")
        else:
            logger.error("Failed to verify signature of JWT MAA")
            result = {
                "type": "urn:apd:Deny",
                "title": "Failed!",
                "detail": "Failed to verify signature of JWT MAA!",
            }
            return JsonResponse(result, status=403)

    except PyJWTError as e:
        logger.error("Failed to decode JWT MAA " + str(e))

        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed to decode JWT MAA - " + str(e),
        }
        return JsonResponse(result, status=403)

    # doing VM config verification
    vm_config_in_jwt = (
        decoded_jwt_maa.get("x-ms-isolation-tee", {})
        .get("x-ms-runtime", {})
        .get("vm-configuration", None)
    )

    if vm_config_in_jwt is None:
        logger.error("VM config not found in JWT ")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "VM config not found in JWT!",
        }
        return JsonResponse(result, status=403)

    if vm_config_in_jwt != HARDCODED_VM_CONFIG:
        logger.error("VM config in JWT does not match hardcoded VM config")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "VM config in JWT does not match hardcoded VM config!",
        }
        return JsonResponse(result, status=403)

    # doing PCR checks
    tpm_values_base64 = (
        decoded_jwt_maa.get("x-ms-runtime", {})
        .get("client-payload", {})
        .get("tpm_values", None)
    )

    if tpm_values_base64 is None:
        logger.error("PCRs not found in JWT ")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "PCRs not found in JWT!",
        }
        return JsonResponse(result, status=403)

    # Decode the TPM values from Base64, it is a JSONified string, so converting to dict as well
    tpm_values_decoded = base64.b64decode(tpm_values_base64).decode("utf-8").strip()
    tpm_values_dict = json.loads(tpm_values_decoded)

    # logger.warn("Only checking PCR 15 for now!!!")
    logger.warn("Not checking PCR values !!!")

    '''
    print("Checking docker image hash")
    if tpm_values_dict["15"] != HARDCODED_PCR_15:
        logger.error("PCRs in JWT does not match hardcoded PCRs")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "PCRs in JWT does not match hardcoded PCRs!",
        }
        return JsonResponse(result, status=403)
    '''
    logger.warn(
        "Not doing any Job or Run checks as of now for Azure AMD SEV attestation!!!"
    )

    # getting public key - Azure base64's it again, so it's base64 of an existing base64 (PEM formatting w/o the BEGIN and END headers)
    public_key_base64_base64 = (
        decoded_jwt_maa.get("x-ms-runtime", {})
        .get("client-payload", {})
        .get("public key", None)
    )

    if public_key_base64_base64 is None:
        logger.error("Public Key not found in JWT ")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Public Key not found in JWT!",
        }
        return JsonResponse(result, status=403)

    public_key_base64 = base64.b64decode(public_key_base64_base64).decode("utf-8")

    result = {
        "type": "urn:apd:Allow",
        "apdConstraints": {"publicKey": public_key_base64},
    }

    return JsonResponse(result)
