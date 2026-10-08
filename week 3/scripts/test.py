import requests

API_KEY = "EpbF0dhZGiyfMms7G8O1VgSg25tx4Q8E"

url = "https://api.shodan.io/api-info"

response = requests.get(
    url,
    params={"key": API_KEY}
)

print(response.status_code)
print(response.text)