
checkPwnedApi(Hallihallo5)

def checkPwnedApi(password): # check
    """
    function to check if the password was pawed -> with API
    """
    # Berechnung des SHA-1 Hash des Passworts
    sha1Password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5Chars, rest = sha1Password[:5], sha1Password[5:]
 
    # Anfrage an die Have I Been Pwned API
    url = f"https://api.pwnedpasswords.com/range/{first5Chars}"
 
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for hash in hashes:
                if rest in hash:
                    return True
        elif response.status_code == 404:
            return False
        else:
            print(f"Fehler beim Abrufen der Daten von Have I Been Pwned (Statuscode {response.status_code}).")
            return False
    except requests.exceptions.Timeout:
        print("Anfrage an Have I Been Pwned API hat zu lange gedauert!")
    except requests.exceptions.RequestException as exception:
        print(f"Fehler bei der Verbindung zur Have I Been Pwned API: {exception}")
        return False
    return False