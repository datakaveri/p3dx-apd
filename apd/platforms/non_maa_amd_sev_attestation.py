from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import base64
import json
import logging
import shutil
import tempfile
import os
import subprocess

logger = logging.getLogger(__name__)

VCEK_CERT_DIR_PATH = os.path.join(os.getcwd(), "apd/platforms/non-maa-assets")
VTPM_PUB_KEY_PATH = os.path.join(
    os.getcwd(), "apd/platforms/non-maa-assets/vtpm_pub_key.pem"
)


def non_maa_amd_sev_check(body):

    # snpguest binary is built and places in /usr/local/bin
    if shutil.which("snpguest") is None:
        logger.error(
            "'snpguest' executable was not found. Cannot run non-MAA attestation without 'snpguest'"
        )
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "'snpguest' executable was not found. Cannot run non-MAA attestation without 'snpguest'",
        }
        return JsonResponse(result, status=403)

    # tpm2_checkquote binary is installed using package manager (`sudo apt install tpm2-tools`)
    if shutil.which("tpm2_checkquote") is None:
        logger.error(
            "'tpm2_checkquote' executable was not found. Cannot run non-MAA attestation without 'tpm2_checkquote'"
        )
        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "'tpm2_checkquote' executable was not found. Cannot run non-MAA attestation without 'tpm2_checkquote'",
        }
        return JsonResponse(result, status=403)

    tmp_folder = tempfile.TemporaryDirectory(prefix="secure_")

    context = body["context"]

    for file_name, encoded_content in context.items():
        binary_content = base64.b64decode(encoded_content)
        output_file_path = os.path.join(tmp_folder.name, file_name)

        try:
            with open(output_file_path, "wb") as output_file:
                output_file.write(binary_content)
        except Exception as e:
            tmp_folder.cleanup()

            logger.error("Error saving binary file " + file_name + " : " + e)
            result = {
                "type": "urn:apd:Deny",
                "title": "Failed!",
                "detail": "Failed!",
            }
            return JsonResponse(result, status=403)

    try:
        verify_guest_report(tmp_folder.name)
        verify_tpm_quote(tmp_folder.name)

    except Exception as e:
        tmp_folder.cleanup()
        logger.error("Error in guest-report/TPM-quote checks " + str(e))

        result = {
            "type": "urn:apd:Deny",
            "title": "Failed!",
            "detail": "Failed!",
        }
        return JsonResponse(result, status=403)

    logger.warn("Not checking PCR values !!!")

    logger.warn(
        "Not doing any Job or Run checks as of now for Azure AMD SEV attestation!!!"
    )

    public_key_file__path = os.path.join(tmp_folder.name, "public_key.pem")

    with open(public_key_file__path, "r") as f:
        public_key_base64 = f.read()

        result = {
            "type": "urn:apd:Allow",
            "apdConstraints": {"publicKey": public_key_base64},
        }

        return JsonResponse(result)


def verify_guest_report(tmp_folder_path):

    try:
        guest_report_file_path = os.path.join(tmp_folder_path, "guest_report.bin")
        result = subprocess.run(
            [
                "snpguest",
                "verify",
                "attestation",
                VCEK_CERT_DIR_PATH,
                guest_report_file_path,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("Verification command output:" + result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error("CalledProcessError executing snpguest:" + e.stderr)
        raise Exception("Failed at snpguest")
    except FileNotFoundError:
        logger.error("Error: File not found.")
        raise Exception("Failed at snpguest")
    except Exception as e:
        logger.error("An unexpected error occurred when executing snpguest :" + str(e))
        raise Exception("Failed at snpguest")


def verify_tpm_quote(tmp_folder_path):

    message_output_file__path = os.path.join(tmp_folder_path, "message_output_file.msg")
    signature_output_file__path = os.path.join(
        tmp_folder_path, "signature_output_file.sig"
    )
    PCR_output_file__path = os.path.join(tmp_folder_path, "PCR_output_file.pcrs")

    try:
        # Construct the full command
        command = [
            "tpm2_checkquote",
            "-u",
            VTPM_PUB_KEY_PATH,
            "-m",
            message_output_file__path,
            "-s",
            signature_output_file__path,
            "-f",
            PCR_output_file__path,
            "-g",
            "sha256",
        ]

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        logger.info(
            "TPM quote verified using the public key of the vTPM" + result.stdout
        )

    except subprocess.CalledProcessError as e:
        logger.error("CalledProcessError executing tpm2_checkquote:" + e.stderr)
        raise Exception("Failed at tpm2_checkquote")
    except FileNotFoundError:
        logger.error("Error: File not found.")
        raise Exception("Failed at tpm2_checkquote")
    except Exception as e:
        logger.error(
            "An unexpected error occurred when executing tpm2_checkquote :" + str(e)
        )
        raise Exception("Failed at tpm2_checkquote")
