import requests
from requests.auth import HTTPBasicAuth

url = "http://172.17.0.2:8181/onos/v1/hosts/00:00:00:00:00:"
url1 = "http://172.17.0.2:8181/onos/v1/hosts/00:00:00:00:01:00/None"

risposta = requests.delete(url1, auth=HTTPBasicAuth("onos", "rocks"))

contatore = 0
for i in range(1, 101):
    if i < 10:
        # print(f"{url}0{i}/None")
        risposta = requests.delete(f"{url}0{i}/None", auth=HTTPBasicAuth("onos", "rocks"))
        if risposta.status_code == 204:
            contatore += 1
    else:
        risposta = requests.delete(f"{url}{i}/None", auth=HTTPBasicAuth("onos", "rocks"))
        if risposta.status_code == 204:
            contatore += 1
print(f"{contatore = }")
print(contatore == 60)
