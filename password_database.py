import hashlib, secrets

user_database = { #El lehet menteni json.dumps()-al egy adatbázis fájlba
    "users": []
}

def check_for_username(username) -> bool:
    username_list = [i[0] for i in user_database["users"]]
    if username in username_list:
        return True
    else:
        return False


def register(username: str, password: str) -> None:
    username = username.encode('idna').decode()
    check = check_for_username(username)
    if check == False:
        password = password.encode('idna')
        salt = secrets.token_urlsafe(16)[0:16]
        hashed_password = hashlib.blake2b(password, salt=salt.encode(), digest_size=32).hexdigest()
        user_database["users"].append([username, hashed_password, salt])
    else:
        print("Ez a felhasználónév már létezik!")
   
if __name__ == '__main__':
    register('alice', 'password') #Elfogadja
    register('bob', 'password') #Elfogadja
    register('bob', 'password') #Ez a felhasználónév már létezik!
    print(user_database) #Írja ki az adatbázist
