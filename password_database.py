import hashlib, secrets

user_database = { #El lehet menteni json.dumps()-al egy adatbázis fájlba
    "users": [] #[felhasználónév, jelszó, só]
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
        print([username, hashed_password, salt])
        user_database["users"].append([username, hashed_password, salt])
    else:
        return False


def login(username: str, password: str) -> None:
    username = username.encode('idna').decode()
    for index, user in enumerate(user_database["users"]):
        if user[0] == username:
            current_user = user_database["users"][index]
            break
    else:
        return False
    
    password = password.encode('idna')
    salt = current_user[2]
    hashed_password = hashlib.blake2b(password, salt=salt.encode(), digest_size=32).hexdigest()
    if hashed_password == current_user[1]:
        print([username, hashed_password, salt])
        return True
    else:
        return False


if __name__ == '__main__':
    print('Regisztráció:')
    register('alice', 'password') #True
    register('bob', 'password') #True
    register('bob', 'password') #False
    
    print('\nBelépés:')
    belepes1 = login('alice', 'password') #True
    belepes2 = login('alice', 'password1') #False
