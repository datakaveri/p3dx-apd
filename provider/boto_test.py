import boto3
import os
import requests
import base64
import time
import json
from .models import Run, Job, App


string1 = b'''Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0
--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"
#cloud-config
cloud_final_modules:
- [scripts-user, always]
--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"
#!/bin/bash
cd /home/ubuntu
githubURL1="'''

string3=b'''"
name1="'''

string5=b'''"
repo1="'''

string7=b'''"
branch1="'''

string9=b'''"
id1="'''

string11=b'''"
./setup_confidential_compute.sh $githubURL1 "$name1" $repo1 $branch1 $id1
--//--'''

INFERENCE_WAIT_TIME = 10
INFERENCE_RETRIES = 80000

class AwsClient:
    i = 12345

    def get_enclave_status_info(self,run_id):
        try:
            res = requests.get("http://3.134.52.151:4000/enclave/state")
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

            if(new_status_info['step'] != 0):
                Run.objects.filter(run_id=run_id).update(status_info=new_status_info)

        return
    

    def execute_enclave(self, app, run_id):
        # start the EC2 instance
        # call server in parent to start the enclave process
        # wait till result there and then return result
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances()
        print (response)

    
        #res = requests.get("http://3.134.52.151:4000/enclave/inference", timeout=40)
        #print("rest result = ", res)

        self.stop_instance()

        #now spin up the EC2 instance..

        print("Modifying user data...")

        instance_id='i-09e4df4cfb8f86bb7'

        githubURL0 = app.git_url
        name0 = app.description
        repo0 = app.name
        branch0 = app.git_branch

        # don't know what this does
        id0 ="7d208144-4f64-42d8-948b-ID3XXXXXXXXX"

        string2=str.encode(githubURL0)  #'''git@github.com:haridk-iudx/DEMO-Nitro-CC-App-repository1.git'''
        string4=str.encode(name0) #b'''Previously demoed and working attestation-over-transport branch code of nitro-enclaves.'''
        string6=str.encode(repo0) #b'''DEMO-Nitro-CC-App-repository1'''

        string8=str.encode(branch0) #b'''attestation-over-transport'''
        string10=str.encode(id0) #b'''7d208144-4f64-42d8-948b-ID1XXXXXXXXd'''

        user_data = string1+string2+string3+string4+string5+string6+string7+string8+string9+string10+string11
        #modify user data... but do this only when the instance is stopped!
        #ec2.modify_instance_attribute(InstanceId=instance_id, Attribute='UserData', Value=user_data)

        print("The USER DATA is: ", user_data)
        userDataBase64=base64.b64encode(user_data).decode("utf-8")
        #ec2.modify_instance_attribute(InstanceId=instance_id, Attribute='userData', Value=user_data)
        print ("UD base 64 = ", userDataBase64)
        ec2.modify_instance_attribute(InstanceId=instance_id, Attribute='userData', Value=userDataBase64)

        response = ec2.describe_instances()
        print (response)

        print ("Spinning up EC2 instance..")

        response = ec2.start_instances(
            InstanceIds=[
                'i-09e4df4cfb8f86bb7',
            ],
            AdditionalInfo='string',
            DryRun=False
        )
        
        # get inference from target flask server that hosts it
        # TODO --> Stop the instance once the inference is done [Hari]
        print("Waiting for result to be served..[1]")

        retry_count = 0
        while True:
            try:
                # get the status of the enclave process
                self.get_enclave_status_info(run_id)

                retry_count = retry_count + 1
                if retry_count == INFERENCE_RETRIES:
                    print("FAILED to fetch inference !!!")
                    break

                print("Trying to fetch inference... try no. ", retry_count)
                res = requests.get("http://3.134.52.151:4000/enclave/inference")
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
                json1 = json.loads(resString, strict=False)
                json2 = json.loads(json1, strict=False)
                res1 = {"inference":json2}
                print("RES1 = ", res1)
                return res1

    def list_instances(self):
        instances = []

        ec2 = boto3.client('ec2')
        response = ec2.describe_instances()
        
        for r in response['Reservations']:
            for i in r['Instances']:
                instances.append(i['InstanceId'])

        #return ['i-09e4df4cfb8f86bb7', 'instance-id-2']
        return instances


    def stop_instance(self):
        #for now we will just stop the instance whose ID we know. In future it could be based on list_instances
        print ("Stopping EC2 instance..")
        ec2=boto3.client('ec2')

        instance_id = 'i-09e4df4cfb8f86bb7'

        response = ec2.stop_instances(
            InstanceIds=[
                'i-09e4df4cfb8f86bb7'
            ],
            Hibernate=False,
            DryRun=False,
            Force=False
        )

        print("Waiting while stopping...")

        waiter=ec2.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id])
        print("done.")
