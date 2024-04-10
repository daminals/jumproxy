# make a get request to the server

import requests

response = requests.get('http://localhost:8000')

print(response)