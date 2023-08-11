import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import itertools
# Dictionary to map hash algorithm names to hashlib functions
hash_algorithms = {
    'SHA256': hashlib.sha256,
    'MD5': hashlib.md5,
    'SHA1': hashlib.sha1,
}
status_label = None
def check_passwords(wordlist_file, username_hash_file, hash_types):
    user_hash_dict = {}

    with open(username_hash_file, 'r') as f:
        text = f.read().splitlines()
        for user_hash in text:
            username, hash_value = user_hash.split(":")
            user_hash_dict[username] = hash_value

    with open(wordlist_file, 'r') as f:
        wordlist = f.read().splitlines()

    found_passwords = []

    for password in wordlist:
        for hash_type in hash_types:
            if hash_type in hash_algorithms:
                hash_func = hash_algorithms[hash_type]
                hashed_password = hash_func(password.encode('utf-8')).hexdigest()

                for username, hash_value in user_hash_dict.items():
                    if hashed_password == hash_value:
                        found_passwords.append((username, password))
                        break

    return found_passwords

def choose_attack_type():
    choice = messagebox.askquestion("Choose Attack Type", "Which attack do you prefer? (Brute Force / Dictionary)")

    if choice == 'yes':  # 'yes' corresponds to Brute Force
        dictionary_attack_button.config(state=tk.DISABLED)
        brute_force_attack(max_password_length=2, possible_characters="")
    else:  # Dictionary Attack
        hash_type_listbox.config(state=tk.NORMAL)
        dictionary_attack_button.config(state=tk.NORMAL)
        brute_force_attack_button.config(state=tk.DISABLED)

def dictionary_attack_gui():
    wordlist_file = wordlist_entry.get()
    username_hash_file = username_hash_entry.get()

    if not wordlist_file or not username_hash_file:
        messagebox.showwarning("File Not Selected", "Please select both wordlist and username-hash files.")
        return

    # Get selected hash types from the listbox
    selected_hash_types = list(hash_type_listbox.curselection())
    hash_types = [hash_type_options[i] for i in selected_hash_types]

    found_passwords = check_passwords(wordlist_file, username_hash_file, hash_types)

    if found_passwords:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "Matching password(s) found (Dictionary Attack):\n")
        for username, password in found_passwords:
            result_text.insert(tk.END, f"Username: {username}, Password: {password}\n")
    else:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "No matching passwords found.")
    global status_label
    status_label.config(text="Attack Completed", fg="green")

def brute_force_attack(max_password_length=2, possible_characters=""):
    for password_length in range(1, max_password_length + 1):
        for password in itertools.product(possible_characters, repeat=password_length):
            print("Generated password (Brute Force Attack):", "".join(password))

def run_selected_attack():
    selected_attack = attack_var.get()
    if selected_attack == 1:  # Brute Force Attack
        max_password_length = int(input("Enter the maximum password length: "))
        possible_characters = input("Enter the characters to be used in the brute force attack: ")
        brute_force_attack(max_password_length, possible_characters)
    elif selected_attack == 2:  # Dictionary Attack
        start_attack_button.config(state=tk.DISABLED)
        dictionary_attack_gui()
        start_attack_button.config(state=tk.NORMAL)


def browse_wordlist():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        wordlist_entry.delete(0, tk.END)
        wordlist_entry.insert(tk.END, file_path)

def browse_username_hash():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        username_hash_entry.delete(0, tk.END)
        username_hash_entry.insert(tk.END, file_path)
def select_wordlist_file():
    file_path = filedialog.askopenfilename()
    wordlist_entry.delete(0, tk.END)
    wordlist_entry.insert(0, file_path)
    status_label.config(text="")

def select_username_hash_file():
    file_path = filedialog.askopenfilename()
    username_hash_entry.delete(0, tk.END)
    username_hash_entry.insert(0, file_path)
    status_label.config(text="")
def clear_results():
    # Clear the results text box
    result_text.delete("1.0", tk.END)

if __name__ == "__main__":
    window = tk.Tk()
    window.title("Password Cracker")

    attack_var = tk.IntVar()
    attack_var.set(0)
    status_label = tk.Label(window, text="", fg="blue")
    status_label.grid(row=6, column=0, columnspan=3, padx=10, pady=10)
    attack_label = tk.Label(window, text="Select Attack Type:")
    attack_label.grid(row=0, column=0, padx=10, pady=10)

    brute_force_radio = tk.Radiobutton(window, text="Brute Force", variable=attack_var, value=1)
    brute_force_radio.grid(row=0, column=1, padx=10, pady=10)

    dictionary_radio = tk.Radiobutton(window, text="Dictionary", variable=attack_var, value=2)
    dictionary_radio.grid(row=0, column=2, padx=10, pady=10)

    start_attack_button = tk.Button(window, text="Start Attack", command=run_selected_attack)
    start_attack_button.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

    hash_type_options = list(hash_algorithms.keys())
    hash_type_listbox = tk.Listbox(window, selectmode=tk.MULTIPLE, height=3)
    for option in hash_type_options:
        hash_type_listbox.insert(tk.END, option)
    hash_type_listbox.grid(row=2, column=1, padx=10, pady=10, columnspan=2)

    wordlist_label = tk.Label(window, text="Wordlist File:")
    wordlist_label.grid(row=3, column=0, padx=10, pady=10)
    wordlist_entry = tk.Entry(window)
    wordlist_entry.grid(row=3, column=1, padx=10, pady=10)
    wordlist_browse_button = tk.Button(window, text="Browse", command=select_wordlist_file)
    wordlist_browse_button.grid(row=3, column=2, padx=10, pady=10)

    username_hash_label = tk.Label(window, text="Username-Hash File:")
    username_hash_label.grid(row=4, column=0, padx=10, pady=10)
    username_hash_entry = tk.Entry(window)
    username_hash_entry.grid(row=4, column=1, padx=10, pady=10)
    username_hash_browse_button = tk.Button(window, text="Browse", command=select_username_hash_file)
    username_hash_browse_button.grid(row=4, column=2, padx=10, pady=10)

    result_text = tk.Text(window, height=10, width=50)
    result_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10)
    clear_results_button = tk.Button(window, text="Clear Results", command=clear_results)
    clear_results_button.grid(row=8, column=0, columnspan=3, padx=10, pady=10)


    window.mainloop()
