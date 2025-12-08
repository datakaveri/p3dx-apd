from binascii import unhexlify, hexlify
from OpenSSL import crypto
from django.http import JsonResponse
import json
from pycose.messages import Sign1Message
from pycose.messages import CoseMessage
import base64
import cbor2
import datetime
import hashlib
import logging

from provider.models import Run, Job, App
from provider.boto_test import AwsClient

from pycose.algorithms import EdDSA
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import KpKty, EC2KpCurve, EC2KpX, EC2KpY
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import VerifyOp
from pycose.keys.keyparam import KpKeyOps
from pycose.keys import CoseKey

logger = logging.getLogger(__name__)

def nitro_check(body):
    b64_cbor_attestation_doc = body["context"]["attestationDocument"]

    cose = ''
    try:
        cose = base64.b64decode(b64_cbor_attestation_doc)
    except base64.binascii.Error:
        logger.error("Invalid attestation document - bad base64")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed!",
        }
        return JsonResponse(result, status=403)

    logger.debug("Got attestation document")

    try:
        pcrs, public_key = verify_attestation_document(cose)
    except Exception as e:
        logger.error("Invalid attestation document")
        logger.error(e)
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed!",
        }
        return JsonResponse(result, status=403)

    item_id = body["item"]["itemId"]
    pcrs_0_1_2 = {x: pcrs[x] for x in [0, 1, 2]}

    logger.debug("Ignoring PCR3")

    client = AwsClient()
    instances = client.list_instances()
    hashed_instances = []

    for i in instances:
        h = hashlib.sha384()
        h.update(b"\0" * 48)
        h.update(i.encode("utf-8"))
        hashed_instances.append(h.hexdigest())

    pcr_4 = pcrs[4]
    
    if pcr_4 not in hashed_instances:
        logger.error("Hashed instance ID (PCR4) not found in running instances")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed!",
        }
        return JsonResponse(result, status=403)
    
    logger.error("WARNING - Disabled PCRs 0, 1, 2 validation")
    running_jobs = (
        Run.objects.filter(status="R")
        .filter(job__resource_id=item_id)
        .filter(job__app__execution_platform=App.AppExecutionPlatforms.AWS_NITRO)
        #.filter(job__app__base_pcrs=pcrs_0_1_2)
    )

    if len(running_jobs) == 0:
        logger.error("Could not find job that matches PCRs 0, 1, 2 and item")
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed!",
        }
        return JsonResponse(result, status=403)

    result = {
        "type": "urn:apd:Allow",
        "apdConstraints": {"publicKey": public_key}
    }
    return JsonResponse(result)

def verify_attestation_document(msg):
    # adding Sign1 tag to message, since it's not being added by AWS now
    msg = b"\xd2" + msg
    
    cose_msg = Sign1Message.decode(msg)

    cbor_att_doc = cose_msg.payload
    att_doc = cbor2.loads(cbor_att_doc)

    # get certificate from AD
    certificate = att_doc["certificate"]

    # get ca bundle from AD
    ca_bundle = att_doc["cabundle"]

    root_cert_pem = bytes(
        """-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
    """.encode(
            "utf-8"
        )
    )

    root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_pem)
    store = crypto.X509Store()
    store.add_cert(root_cert)

    for cert in ca_bundle:
        intermediate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        store.add_cert(intermediate)

    att_doc_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)

    print("Certificate issue time - ", att_doc_cert.get_notBefore())
    print("Certificate exp time - ", att_doc_cert.get_notAfter())

    # TODO setting time of example attestation document
    # validation_date = datetime.datetime.strptime("2022-11-30 10:30", "%Y-%m-%d %H:%M")
    # store.set_time(validation_date)

    store_ctx = crypto.X509StoreContext(store, att_doc_cert)

    try:
        store_ctx.verify_certificate()
        store_ctx.get_verified_chain()
    except crypto.X509StoreContextError as e:
        raise Exception("Failed to validate AD")

    public_key = att_doc_cert.get_pubkey()

    cert_public_numbers = public_key.to_cryptography_key().public_numbers()
    x = cert_public_numbers.x
    y = cert_public_numbers.y

    key_as_dict = {
        KpKty: KtyEC2,
        EC2KpCurve: "P_384",
        KpKeyOps: [VerifyOp],
        EC2KpX: x.to_bytes(len(str(x)), byteorder="big"),
        EC2KpY: y.to_bytes(len(str(y)), byteorder="big"),
    }
    cose_key = CoseKey.from_dict(key_as_dict)

    cose_msg.key = cose_key

    res = cose_msg.verify_signature()
    if not res:
        raise Exception("Failed to validate AD signature")

    pcrs = att_doc["pcrs"]

    proper_pcrs = {}
    for val in pcrs:
        proper_pcrs[val] = hexlify(pcrs[val]).decode("ascii")

    print(proper_pcrs)

    public_key = base64.b64encode(att_doc["public_key"]).decode('ascii')

    return proper_pcrs, public_key
