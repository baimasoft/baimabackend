import requests

res = requests.post("http://127.0.0.1:8000/api/v1/orders/refund")

print(res.text)