import os
import time
import msvcrt
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
import hashlib
import platform
import subprocess
import atexit
import signal
import sys

def get_cpu_info():
    if platform.system() == "Windows":
        command = "wmic cpu get ProcessorId"
        result = subprocess.check_output(command, shell=True).decode().strip().split()
        return result[-1] if len(result) > 1 else ""
    elif platform.system() == "Linux":
        command = "cat /proc/cpuinfo | grep 'Serial' | awk '{print $3}'"
    elif platform.system() == "Darwin":
        command = "sysctl -n machdep.cpu.brand_string"
    return subprocess.check_output(command, shell=True).decode().strip()

def get_motherboard_serial():
    if platform.system() == "Windows":
        command = "wmic baseboard get SerialNumber"
        result = subprocess.check_output(command, shell=True).decode().strip().split()
        return result[-1] if len(result) > 1 else ""
    elif platform.system() == "Linux":
        command = "sudo dmidecode -s baseboard-serial-number"
    elif platform.system() == "Darwin":
        command = "ioreg -l | grep IOPlatformSerialNumber | awk '{print $4}' | tr -d '\"'"
    return subprocess.check_output(command, shell=True).decode().strip()

def get_system_uuid():
    if platform.system() == "Windows":
        command = "wmic csproduct get UUID"
        result = subprocess.check_output(command, shell=True).decode().strip().split()
        return result[-1] if len(result) > 1 else ""
    elif platform.system() == "Linux":
        command = "cat /sys/class/dmi/id/product_uuid"
    elif platform.system() == "Darwin":
        command = "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID"
    return subprocess.check_output(command, shell=True).decode().strip()

def generate_master_key():
    cpu_info = get_cpu_info()
    motherboard_serial = get_motherboard_serial()
    system_uuid = get_system_uuid()

    combined_info = cpu_info + motherboard_serial + system_uuid
    master_key = hashlib.sha256(combined_info.encode()).hexdigest()
    return master_key

def deriveKey(text, salt, key_size=32):
    return PBKDF2(text, salt, dkLen=key_size, count=1000000)

def unpadData(data):
    padding_length = data[-1]
    return data[:-padding_length]

def decryptFile(input_path, output_path, key_text, writeData=True):
    with open(input_path, 'rb') as file:
        encrypted_data = file.read()
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = deriveKey(key_text, salt, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    data = unpadData(padded_data)
    if writeData:
        with open(output_path, 'wb') as file:
            file.write(data)
    else: return data

def derive_key(text, salt, key_size=32):
    return PBKDF2(text, salt, dkLen=key_size, count=1000000)

def pad_data(data):
    padding_length = 16 - (len(data) % 16)
    return data + (padding_length * chr(padding_length)).encode()

def encrypt_file(input_path, output_path, key_text, isString=False):
    if isString: file_data = input_path
    else:
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

def getFileName():
    while True:
        print(" > Enter the name of the file you would like to change\n > include the file extension")
        out = input(" > ")
        print(f" > '{out}' is this correct? (y/n)")
        key = msvcrt.getch().decode("utf-8")
        if key == "y": return out

def infoFile(name, key):
    master = generate_master_key()
    infoDir = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1])+"\\info.gtfo"

    if os.path.exists(infoDir):
        print()
        data = decryptFile(infoDir, "", master, False).decode("utf-8")
        print(data)
        data += f"{name},{key}\n"
        encrypt_file(data.encode("utf-8"), infoDir, master, True)
    else:
        with open(infoDir, "w") as f: f.write("")
        data = f"{name},{key}\n"
        encrypt_file(data.encode("utf-8"), infoDir, master, True)
        
    


def encryptPage():
    while True:
        print("\n", "File Type".center(51), "\n")
        print(" > Are you encrypting a folder or a single file?\n > ('folder'/'file')")
        select = input(" > ").lower().strip()

        if select == "folder":
            select = 1
            break
        elif select == "file":
            select = 0
            break
        else:
            print(" > Enter a valid response")
            time.sleep(1)
        os.system("cls")

    os.system("cls")
    print("\n", "Select the filepath or folder path".center(51), "you would like to encrypt".center(51), "\n")
    while True:
        if select == 0: path = openFile()
        else: path = openFolder()

        if os.path.exists(path):
            fileList = getFiles(path)
            if "." in path: print(f" > '{path}'\n > Is this correct? (y/n)\n > ")
            else: print(f" >\n > '{path}'\n > There are {len(fileList)} file(s) in this directory\n > Is this correct? (y/n)\n > ")
            key = str(msvcrt.getch())
            if "y" in key: break
            elif "q" in key: os._exit(0)
        else:
            print(" > File/Folder path does not exist\n > ")
            input()
    
    '''
    file renaming, didnt finish, seemed like a pain.
    also add something to check if a file already exists with the same name that has been encrypted

    os.system("cls")
    print("\n", "Rename File(s)".center(51))
    if select == 0:
        while True:
            print(" > Would you like to rename the file? (y/n)")
            key = msvcrt.getch().decode("utf-8")
            if key == "y":
                newName = input('Enter new file name\n > ') + f".{fileList[0].split('.')[1]}"
                fileList[0] = "/".join(fileList[0].split("/")[0:-1]) + f"/{newName}"
                print(f" > '{newName}'\n > Is this correct? (y/n)")
                key = msvcrt.getch().decode("utf-8")
                if key == "y": break
                else: key = ""
            else: break
    else:
        while True:
            print(" > Would you like to rename a file? (y/n)")
            key = msvcrt.getch().decode("utf-8")
            if key == "y":
                file = getFileName()
                found = False
                for item in fileList:
                    if file in item:
                        found = True
    '''



                

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
        elif "q" in key: os._exit(0)

    try:
        finalKey = ""
        for item in keys:
            finalKey += item.strip()
        
        time.sleep(.5)
        os.system('cls')
        print("\n", "Starting Encryption".center(51), "\n")

        currDir = "/".join(os.path.realpath(__file__).rsplit("\\")[0:-1]) + "/files"
        if not os.path.exists(currDir): os.mkdir(currDir)
        print(currDir)
        for file in fileList:
            fileName = file.split('/')[-1]
            infoFile(fileName, finalKey)
            print(f" > Encrypting {fileName}")
            encrypt_file(file, currDir + f"/{fileName.split('.')[0]}.gtfo", finalKey)
            print(f" > '{fileName}' Saved")
    except Exception as e: print(e)

    input("\n > Press 'enter' to exit")

def checkFiles():
    master = generate_master_key()
    infoDir = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1])+"\\info.gtfo"
    data = decryptFile(infoDir, "", master, False).decode("utf-8").split("\n")

    files = ""
    for items in data:
        if os.path.exists(items.split(","[0])): files = f"{items}\n"

    encrypt_file(data.encode("utf-8"), infoDir, master, True)

def openFile(customType=()):
    root = tk.Tk()
    root.withdraw()
    if len(customType) > 0:
        initDir = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1]) + "\\files"
        file_path = filedialog.askopenfilename(
            title="Select a file",
            initialdir=initDir,
            filetypes=(customType, ("All Files", "*.*"))
            )
    else: file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=(("All files", "*.*"),))

    return file_path

def openFolder():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askdirectory(title="Select a Folder",)
    return file_path

def decryptPage():
    path = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1]) + "\\files"
    if not os.path.exists(path):
        print("\n")
        print("No file have been encrypted".center(51), "Press 'enter' to exit".center(51))
        input()

    files = getFiles(path)

    if len(files) == 0:
        print("\n")
        print("No file have been encrypted".center(51), "Press 'enter' to exit".center(51))
        input()
    else:
        while True:
            print("\n", "Select a file to decrypt".center(51), "\n")
            time.sleep(.3)
            path = openFile(("GTFO files", "*.gtfo"))
            print(f" > {path}\n > Is this correct? (y/n)")

            key = str(msvcrt.getch())
            if "y" in key: break
            elif "q" in key: os._exit(0)
            else: os.system("cls")

    time.sleep(.3)
    os.system("cls")
    print("\n", "Enter all keys".center(51), "\n")

    keys = []
    for i in range(7):
        print(f" > Key #{i+1}:")
        keys.append(input(" > "))
    
    while True:
        os.system("cls")
        print("\n", "Edit Keys".center(51), "\n")
        for i, item in enumerate(keys):
            print(f" > Key #{i+1}: {item}")
        print("\n > Do you want to edit any of these keys?\n > (y/n)")
        
        key = msvcrt.getch().decode("utf-8")
        if key == "n": break
        elif key == "q": os._exit(0)
        else:
            print(" > Which key would you like to edit? (1-7)")
            try: 
                select = int(input(" > "))
                if select >= 1 and select <= 7:
                    keys[select-1] = input(" > Enter the new key\n > ")
                else:
                    print(" > Enter a valid number")
                    time.sleep(1)
            except:
                print(" > Enter a valid number")
                time.sleep(1)
    
    finalKey = ""
    for item in keys:
        finalKey += item.strip()

    '''
    selection = 0
    while True:
        os.system('cls')
        print("\n", "Select Decryption Method".center(51), "\n")
        if selection == 0: print("--> Temp <--        permanent    ".center(51))
        else: print("    Temp        --> permanent <--".center(51))

        key = str(msvcrt.getch())
        if "K" in key or "a" in key: selection = 0
        elif "M" in key or "d" in key: selection = 1
        elif ' ' in key or '\\r' in key:
            break
        elif "q" in key: os._exit(0)

        time.sleep(.1)
    '''
    
    os.system("cls")
    tempPath = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1])+"\\tempFiles"
    if not(os.path.exists(tempPath)):
        os.mkdir(tempPath)

    master = generate_master_key()
    infoDir = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1])+"\\info.gtfo"
    data = decryptFile(infoDir, "", master, False).decode("utf-8").split("\n")
    fileName = path.split("/")[-1].split(".")[0]

    fileExtension = ""
    for items in data:
        if fileName in items:
            fileExtension = items.split(".")[1].split(",")[0]
    
    if fileExtension == "":
        os.system("cls")
        print("An error occured getting the file extension".center(51))
        input()
        os._exit(1)
    
    tempPath = tempPath+f"\\{fileName}.{fileExtension}"

    decryptFile(path, tempPath, finalKey)

    print("\n", " > Where do you want to save the file?")
    time.sleep(.35)
    savePath = openFolder()
    os.rename(tempPath, savePath+f"/{fileName}.{fileExtension}")
    print(" > File moved successfully")
    
    print("\n", " > Do you want to open the file? (y/n)")
    while True:
        key = msvcrt.getch().decode("utf-8")
        if key == "y":
            os.startfile(tempPath)
            break

def master():
    os.system("cls")
    inps = []
    for i in range(7):
        inps.append(input())
    masterKey = hashlib.sha256("".join(inps).encode()).hexdigest()
    # encrypt inps then check it with a hardcoded encrypted key to see if it was right
    # if it was right then run the code below

    master = generate_master_key()
    infoDir = "\\".join(os.path.realpath(__file__).rsplit("\\")[0:-1])+"\\info.gtfo"
    data = decryptFile(infoDir, "", master, False).decode("utf-8").split("\n")
    for i, item in enumerate(data):
        try:
            print(f"file: {item.split(',')[0]}\nKey: {item.split(',')[1]}\n({i+1}/{len(data)-1})\n")
            input()
        except: break

def main():
    os.system('mode 51,23')
    os.system('color C')
    startDisplay()

    checkFiles()

    # K = left, M = right
    selection = 0
    slashCount = 0
    while True:
        os.system('cls')
        print("\n", "Are you encrypting or decrypting?".center(51), "\n")
        if selection == 0: print("--> Encryption <--        Decryption    ".center(51))
        else: print("    Encryption        --> Decryption <--".center(51))

        key = str(msvcrt.getch())
        if "K" in key or "a" in key: selection = 0
        elif "M" in key or "d" in key: selection = 1
        elif ' ' in key or '\\r' in key: break
        elif "q" in key: os._exit(0)
        elif "/" in key: slashCount += 1

        if slashCount == 3:
            master()
            slashCount = 4

        time.sleep(.1)
    
    os.system("cls")

    # C:\Users\thetr\Documents\Python
    if selection == 0: encryptPage()
    else: decryptPage()

if __name__ == "__main__":
    main()
    