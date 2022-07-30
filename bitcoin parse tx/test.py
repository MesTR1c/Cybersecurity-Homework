import requests
tx="736cd2c1b5cc3c25e51124048874f975af5ead09d7ee3ddaef56ea01fae73d4b"
url="https://api.blockcypher.com/v1/btc/test3/txs/"+tx
response = requests.get(url)
print(response.text)
with open("C://Users//86180//Desktop//bitcoin parse tx//result.txt","w") as f:
    print("writing!!!")
    f.write(response.text)
