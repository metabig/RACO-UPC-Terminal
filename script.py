#!/usr/bin/python3
import requests
import re
import os
import signal
import sys
import urllib3
from getpass import getpass
from inscriptis import get_text
from urllib.parse import urlparse
from urllib.parse import parse_qs

USERNAME = ""
PASSWORD = ""

class color:
  PURPLE = '\033[95m'
  CYAN = '\033[96m'
  DARKCYAN = '\033[36m'
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'
  END = '\033[0m'

#Config
urllib3.disable_warnings()

#Ctrl+C handler
def def_handler(sig, frame):
  print(color.BOLD + color.RED + '\n[!] Sortint...\n' + color.END)
  sys.exit(1)

#Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def getToken():
  try:
    sys.stdout.write("\r[■□□□□□□□□]")
    sys.stdout.flush()
    r = requests.get("https://api.fib.upc.edu/v2/o/authorize/?client_id=9zrxDnrxtyFDEkiy9EhnTIuZGhU1HLnXO0NR431e&redirect_uri=http://fake.url&response_type=code", allow_redirects=False)
    sys.stdout.write("\r[■■□□□□□□□]")
    sys.stdout.flush()

    r = requests.get("https://api.fib.upc.edu/"+r.headers['Location'], allow_redirects=False)
    ssoupcedu_url = r.headers['Location']

    sys.stdout.write("\r[■■■□□□□□□]")
    sys.stdout.flush()
    r = requests.get(ssoupcedu_url, allow_redirects=False)
    sys.stdout.write("\r[■■■■□□□□□]")
    sys.stdout.flush()
    data = {
      "adAS_mode":"authn", 
      "adAS_username": USERNAME,
      "adAS_password": PASSWORD
    }

    r = requests.post(ssoupcedu_url, cookies=dict(r.cookies), data=data, allow_redirects=False)
    sys.stdout.write("\r[■■■■■□□□□]")
    sys.stdout.flush()

    r = requests.get(r.headers['Location'], cookies=dict(r.cookies),  allow_redirects=False)
    nicecookies = dict(r.cookies)
    sys.stdout.write("\r[■■■■■■□□□]")
    sys.stdout.flush()

    r = requests.get("https://api.fib.upc.edu/" + r.headers['Location'], cookies=nicecookies,  allow_redirects=False)
    csrfmiddlewaretoken = re.findall(r'csrfToken: "(.*?)"', r.text)[0]
    sys.stdout.write("\r[■■■■■■■□□]")
    sys.stdout.flush()
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Referer': 'https://api.fib.upc.edu/v2/o/authorize/?client_id=9zrxDnrxtyFDEkiy9EhnTIuZGhU1HLnXO0NR431e&redirect_uri=http://fake.url&response_type=code',
    }

    data = 'csrfmiddlewaretoken=' + csrfmiddlewaretoken + '&redirect_uri=http://fake.url&scope=read&client_id=9zrxDnrxtyFDEkiy9EhnTIuZGhU1HLnXO0NR431e&response_type=code&allow=Authorize'
    response = requests.post('https://api.fib.upc.edu/v2/o/authorize/?client_id=9zrxDnrxtyFDEkiy9EhnTIuZGhU1HLnXO0NR431e&redirect_uri=http://fake.url&response_type=code', headers=headers, cookies=nicecookies, data=data, verify=False, allow_redirects=False)
    sys.stdout.write("\r[■■■■■■■■□]")
    sys.stdout.flush()
    final_url = response.headers['Location']
    parsed_url = urlparse(final_url)

    code = parse_qs(parsed_url.query)['code'][0]

    url = "https://api.fib.upc.edu/v2/o/token"

    payload='grant_type=authorization_code&redirect_uri=http://fake.url&code=' + code + '&client_id=9zrxDnrxtyFDEkiy9EhnTIuZGhU1HLnXO0NR431e&client_secret=W6aa8Qu26E1mJEhkRA7h2VuCDrcHUBmszOWI9hHU2Tn6EgKOIH9oxWBBQTFbiWeguCnFGzIoVzUVydTjKt4EblbG91vFBYi64NwNSzLdN39eZZVObA6AxruGtHQWc2fp'
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': 'csrftoken=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    sys.stdout.write("\r[■■■■■■■■■]")
    sys.stdout.flush()
    token = response.json()['access_token']
  except:
    print (color.BOLD + "\nError logging in. Wrong username or password? Try again..." + color.END)
    raise
  return token

def makeRequest(url):
  headers = {
    'Authorization': 'Bearer ' + token,
    'Cookie': 'csrftoken=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  }

  return requests.get(url, headers=headers)

if __name__ == '__main__':
  if (USERNAME == "" or PASSWORD == ""):
    USERNAME = input("Username: ")
    PASSWORD = getpass()


  os.system('clear')
  print(color.GREEN + "Verificant..." + color.END)
  token = getToken()


  os.system('clear')
  print(color.GREEN + "Obtenint dades..." + color.END)
  sys.stdout.write("\r[■□□□]")
  sys.stdout.flush()
  responseJSON = makeRequest("https://api.fib.upc.edu/v2/jo?format=json").json()
  sys.stdout.write("\r[■■□□]")
  sys.stdout.flush()
  assigJSON = makeRequest("https://api.fib.upc.edu/v2/jo/assignatures?format=json").json()
  sys.stdout.write("\r[■■■□]")
  sys.stdout.flush()
  avisosJSON = makeRequest("https://api.fib.upc.edu/v2/jo/avisos?format=json").json()['results']
  sys.stdout.write("\r[■■■■]")
  sys.stdout.flush()
  os.system('clear')


  print("Benvingut " + responseJSON['nom'] + " " + responseJSON['cognoms'] + " (" + responseJSON['username'] + ") ")
  print(responseJSON['email'])

  assignatures = []
  
  print(color.BOLD + "\nASSIGNATURES: " + color.END)
  for r in assigJSON['results']:
    print(r['id'] + "\tGrup: " + r['grup'])
    assignatures.append(r['id'])
  
  
  print(color.BOLD + "\nAVISOS: " + color.END)
  for a in assignatures:
    print(a + ": ")
    for avis in avisosJSON:
      if avis['codi_assig'] == a:
        print(color.BOLD + "(" + str(avis['id']) + ")=====" + avis['titol'] + color.END)

  while True:
    avis_id = input(color.CYAN + color.BOLD + ">>>>>>> " + color.END + color.BOLD + "AVIS ID: " + color.END)
    if str(avis_id) in ["h", "help", "ls"]:
      for a in assignatures:
        print(a + ": ")
        for avis in avisosJSON:
          if avis['codi_assig'] == a:
            print(color.BOLD + "(" + str(avis['id']) + ")=====" + avis['titol'] + color.END)
    for a in avisosJSON:
      if str(avis_id) == str(a['id']):
        print(color.BOLD + a['titol'] + color.END)
        print(get_text(a['text']))
  