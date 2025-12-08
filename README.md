# Setup

- Create virtualenv in a directory
```
virtualenv -p python3 .
```

- Clone repository in the directory
```
git clone https://github.com/datakaveri/p3dx-apd
```

- Install requirements
```
pip3 install -r requirements.txt
```

- In the enclave-apd-poc directory, start the task cluster
```
python3 manage.py qcluster
```

- Then start the server. Will start at port 8000 **on 127.0.0.1**
```
python3 manage.py runserver
```

**NOTE : THIS SERVER IS CONFIGURED TO RUN AT THE HOSTNAME `authenclave.iudx.io` ON HTTPS**. SEE `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` in `enclave_apd/settings.py` TO CHANGE THIS.

- To expose the server **publicly** at port 8000, run
```
python3 manage.py runserver 0.0.0.0:8000
```

_You can run the `qcluster` and `runserver` steps in tmux sessions to make it easy to manage_

- To create a new job, go to `http://localhost:8000/provider/view_create_job/`

- To go to the admin console, go to `http://localhost:8000/admin/`

- Django will usually restart whenever a code change is made, but the cluster may at times not work properly. So if any changes are made to the cluster related code, like `boto-test.py` it's best to restart the cluster by just killing the `qcluster` command and then running it again.


