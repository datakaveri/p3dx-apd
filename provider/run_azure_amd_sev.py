import os
import requests
import base64
import time
import json
import secrets
from .models import Run, Job, App
from django.conf import settings
from datetime import datetime, timezone

INFERENCE_WAIT_TIME = 10
INFERENCE_RETRIES = 80000

azure_amd_server_username = settings.AZURE_AMD_SERVER_USERNAME
azure_amd_server_password = settings.AZURE_AMD_SERVER_PASSWORD

class AzureAmdSevClient:
    url = "https://enclave-manager-amd.iudx.io"

    def get_enclave_status_info(self, run_id):
        try:
            res = requests.get(self.url + "/enclave/state", auth=(azure_amd_server_username, azure_amd_server_password))
        except requests.exceptions.Timeout as errt:
            print ("StatusInfo: Timeout Error : ", errt)
        except requests.exceptions.ConnectionError as errc:
            print ("StatusInfo: Connection Error : ", errc)
        except requests.exceptions.ConnectTimeout as errct:
            print ("StatusInfo: ConnectTimeout Error : ", errct)
        except requests.exceptions.RequestException as err:
            print ("StatusInfo: Unexpected error !!! : ", err)
        else:
            if res.status_code != 200:
                print ("StatusInfo: Non 200 error\n")

            resString = res.content.decode('UTF-8')
            new_status_info = json.loads(resString, strict=False)

            if 'step' in new_status_info:
                if(new_status_info['step'] != 0):
                    Run.objects.filter(run_id=run_id).update(status_info=new_status_info)
            else:
                print("Failed to get correct state : ", resString)

        return
    
    def execute_enclave(self, app, run_id, dataset_name, resource_server_url, additional_context):
        # call the azure_amd server
        start_enclave_req = {"id": str(secrets.randbelow(10000)), "repo": app.name, "branch": app.git_branch, "url": app.git_url, "name" : app.description, "dataset_name": dataset_name, "rs_url": resource_server_url, "context": additional_context}
        
        started = requests.post(self.url + "/enclave/deploy", auth=(azure_amd_server_username, azure_amd_server_password), json=start_enclave_req)
        if started.status_code != 200:
            resString = started.content.decode('UTF-8')
            string = "Failed to Create azure_amd Job" + resString + str(started.status_code)
            r = Run.objects.get(run_id=run_id)
            r.status = 'F'
            r.ended_at=datetime.now(timezone.utc)
            r.save()
            raise Exception(string)

        retry_count= 0
        while True:
            try:
                # get the status of the enclave process
                self.get_enclave_status_info(run_id)
                time.sleep(5)

                retry_count = retry_count + 1
                if retry_count == INFERENCE_RETRIES:
                    print("FAILED to fetch inference !!!")
                    break

                print("Trying to fetch inference... try no. ", retry_count, " at ", time.asctime())
                res = requests.get(self.url + "/enclave/inference", auth=(azure_amd_server_username, azure_amd_server_password))
            except requests.exceptions.Timeout as errt:
                print ("Timeout Error : ", errt)
                print("res = ", res)
                time.sleep(INFERENCE_WAIT_TIME)
                continue
            except requests.exceptions.ConnectionError as errc:
                print ("Connection Error : ", errc)
                #print("res = ", res)
                time.sleep(INFERENCE_WAIT_TIME)
                continue
            except requests.exceptions.ConnectTimeout as errct:
                print ("ConnectTimeout Error : ", errct)
                print("res = ", res)
                time.sleep(INFERENCE_WAIT_TIME)
                continue
            except requests.exceptions.RequestException as err:
                print ("Unexpected error !!! : ", err)
                break
            else:
                
                if res.status_code == 403:
                    print ("403 error.. inference not available yet.\n")
                    continue

                print ("Obtained inference !!!")
                
                # update status one last time before returning 
                self.get_enclave_status_info(run_id)
                
                resString = res.content.decode('UTF-8')
                json2 = json.loads(resString, strict=False)
                print("JSON RESP = ", json2)
                return json2
