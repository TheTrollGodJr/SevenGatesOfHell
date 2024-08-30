import os
import time
import msvcrt
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ctypes
import sys

def deriveKey(text, salt, key_size=32):
    return PBKDF2(text, salt, dkLen=key_size, count=1000000)

def unpadData(data):
    padding_length = data[-1]
    return data[:-padding_length]

def decryptFile(input_path, output_path, key_text):
    with open(input_path, 'rb') as file:
        encrypted_data = file.read()
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = deriveKey(key_text, salt, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    data = unpadData(padded_data)
    with open(output_path, 'wb') as file:
        file.write(data)

def derive_key(text, salt, key_size=32):
    return PBKDF2(text, salt, dkLen=key_size, count=1000000)

def pad_data(data):
    padding_length = 16 - (len(data) % 16)
    return data + (padding_length * chr(padding_length)).encode()

def encrypt_file(input_path, output_path, key_text):
    with open(input_path, 'rb') as file:
        file_data = file.read()
    salt = get_random_bytes(16)
    key = derive_key(key_text, salt, 32)
    padded_data = pad_data(file_data)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    encrypted_data = salt + iv + ciphertext
    with open(output_path, 'wb') as file:
        file.write(encrypted_data)

def startDisplay():
    menu = ["  ______  _______ _______________________ _______  ",
            " / ___  \(  ____ (  ___  \__   __(  ____ (  ____ \ ",
            " \/   )  | (    \| (   ) |  ) (  | (    \| (    \/ ",
            "     /  /| |     | (___) |  | |  | (__   | (_____  ",
            "    /  / | | ____|  ___  |  | |  |  __)  (_____  ) ",
            "   /  /  | | \_  | (   ) |  | |  | (           ) | ",
            "  /  /   | (___) | )   ( |  | |  | (____//\____) | ",
            "  \_/    (_______|/     \|  )_(  (_______\_______) ",
            " _______ _______                                   ",
            " (  ___  (  ____ \                                 ",
            " | (   ) | (    \/                                 ",
            " | |   | | (__                                     ",
            " | |   | |  __)          _______  _        _       ",
            " | |   | | (   |\     /|(  ____ \( \      ( \      ",
            " | (___) | )   | )   ( || (    \/| (      | (      ",
            " (_______|/    | (___) || (__    | |      | |      ",
            "               |  ___  ||  __)   | |      | |      ",
            "               | (   ) || (      | |      | |      ",
            "               | )   ( || (____/\| (____/\| (____/\\",
            "               |/     \|(_______/(_______/(_______/"]

    display = []

    for i in range(20):
        display.append("")
    #   '''
    print(display)
    for i in range(51):
        for j in range(8):
            display[j] += menu[j][i]
        os.system('cls')
        print("\n".join(display))
        time.sleep(.04)

    for i in range(8):
        for j in range(18):
            if i > 4 and j > 12:
                continue
            display[i+8] += menu[i+8][j]
        os.system('cls')
        print("\n".join(display))
        time.sleep(.04)
    #'''

    for i in range(4): display[i+16] += "               "
    for i in range(3): display[i+13] += "  "
    display[12] = display[12][:15]

    for i in range(36):
        #print(menu[13][16])
        for j in range(8):
            display[j+12] += menu[j+12][i+15]
        os.system('cls')
        print("\n".join(display))
        time.sleep(.05)


    print("\n")
    input("Press 'enter' to continue".center(51))
    os.system('cls')

def selectionPage(page, selection):
    os.system('cls')
    if page == 0:
        print("\n", "Are you encrypting or decrypting?".center(51), "\n")
        if selection == 0: print("--> Encryption <--        Decryption    ".center(51))
        else: print("    Encryption        --> Decryption <--".center(51))

def getFiles(path):
    fileList = []
    if os.path.isfile(path):
        fileList.append(path)
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                fileList.append(file_path)
    return fileList

def encryptPage():
    print("\n", "Enter the filepath or folder path".center(51), "you would like to encrypt".center(51), "\n")
    while True:
        path = input(" > ")
        if os.path.exists(path):
            fileList = getFiles(path)
            if "." in path: print(f" > '{path}'\n > Is this correct? (y/n)\n > ")
            else: print(f" >\n > '{path}'\n > There are {len(fileList)} file(s) in this directory\n > Is this correct? (y/n)\n > ")
            key = str(msvcrt.getch())
            if "y" in key: break
            elif "q" in key: os._exit(1)
        else:
            print(" > File/Folder path does not exist\n > ")

    print(" > submitted")
    time.sleep(.75)
    os.system("cls")
    print("\n")
    print("The file(s) will be encrypted 7 times".center(51))
    print("You need to enter a 'key' for each layer".center(51))
    print("of encryption".center(51))
    print("")
    print("These keys are what you will use to decrypt".center(51))
    print("your file later to access them".center(51))
    print("Make sure you will not forget your keys".center(51))
    print("")
    print("You can edit your keys later".center(51), "")

    keys = []

    for i in range(7):
        print(f" > Enter key #{i+1}:")
        keys.append(input(" > "))
        '''
        while True:
            tempKey = input(" > ")
            print(f" >\n > '{tempKey}'\n > Is this correct? (y/n)\n")
            key = str(msvcrt.getch())
            if "y" in key:
                keys.append(tempKey)
                break
            elif "q" in key: os._exit(1)
        '''
    
    while True:
        os.system('cls')
        print("\n", "Would you like to edit any of the keys?".center(51))
        print("(y/n)".center(51))
        for i, item in enumerate(keys):
            print(f" > Key #{i+1} = {item}")
        
        key = str(msvcrt.getch())
        if "y" in key:
            while True:
                try: confirm = int(input(" > Select which key to change (1-7)\n > "))
                except: print(" > Please enter a valid number\n > ")

                if confirm >= 1 and confirm <= 7:
                    print(f" > Enter the key for key #{confirm}")
                    keys[confirm-1] = input(" > ")
                    break

        elif "n" in key: break
        elif "q" in key: os._exit(1)

    try:
        finalKey = ""
        for item in keys:
            finalKey += item.strip()
        
        time.sleep(.5)
        os.system('cls')
        print("\n", "Starting Encryption".center(51), "\n")

        currDir = "/".join(os.path.realpath(__file__).rsplit("\\")[0:-1]) + "/files"
        print(currDir)
        for file in fileList:
            print(f"filepath={file}, filename={file.rsplit('\\')[-1]}")
            fileName = file.rsplit('\\')[-1]
            print(f" > Encrypting {fileName}")
            encrypt_file(file, currDir + f"/{fileName.split('.')[0]}.gtfo", finalKey)
            print(f" > '{fileName}' Saved")
    except Exception as e: print(e)

    input("\n > Press 'enter' to exit")

def decryptPage():
    pass

if __name__ == "__main__":
    os.system('mode 51,23')
    os.system('color C')
    startDisplay()

    # K = left, M = right
    selection = 0
    page = 0
    while True:
        os.system('cls')
        print("\n", "Are you encrypting or decrypting?".center(51), "\n")
        if selection == 0: print("--> Encryption <--        Decryption    ".center(51))
        else: print("    Encryption        --> Decryption <--".center(51))

        key = str(msvcrt.getch())
        if "K" in key or "a" in key: selection = 0
        elif "M" in key or "d" in key: selection = 1
        elif ' ' in key or '\\r' in key:
            selection = 0
            if selection == 1: page = 1
            break
        elif "q" in key: os._exit(1)\

        time.sleep(.1)
    
    os.system("cls")

    # C:\Users\thetr\Documents\Python
    if page == 0: encryptPage()
    else: decryptPage()
        

