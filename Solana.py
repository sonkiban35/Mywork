import hashlib
import random
import requests
import time
from colorama import Fore
from tronpy import Tron
from tronpy.keys import PrivateKey as TronPrivateKey

# Set up Tron client
tron_client = Tron()

def generate_eth_address():
    private_key = ''.join(random.choice('0123456789abcdef') for _ in range(64))
    keccak = hashlib.sha3_256()
    keccak.update(private_key.encode())
    eth_address = "0x" + keccak.hexdigest()[-40:]
    return private_key, eth_address

def generate_solana_address():
    private_key = ''.join(random.choice('0123456789abcdef') for _ in range(64))
    # Use the first 32 bytes of the private key as a placeholder for the public key
    # (In practice, use actual Solana key generation for accuracy)
    public_key = private_key[:32]
    return private_key, public_key

def generate_tron_address():
    private_key = ''.join(random.choice('0123456789abcdef') for _ in range(64))
    tron_key = TronPrivateKey.fromhex(private_key)
    tron_address = tron_key.public_key.to_base58check_address()
    return private_key, tron_address

def check_eth_balance(address):
    api_key = 'YOUR_ETHERSCAN_API_KEY'
    url = f'https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data['status'] == '1':
            balance_ether = float(data['result']) / 10 ** 18
            return balance_ether
    return None

def check_solana_balance(address):
    url = "https://api.mainnet-beta.solana.com"
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    }
    
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if "result" in data:
            balance_sol = data["result"]["value"] / 10 ** 9  # Convert lamports to SOL
            return balance_sol
    return None

def check_tron_balance(address):
    balance_trx = tron_client.get_account_balance(address)
    return balance_trx

while True:
    # Generate and check balances for each network
    eth_private_key, eth_address = generate_eth_address()
    sol_private_key, sol_address = generate_solana_address()
    tron_private_key, tron_address = generate_tron_address()

    # Ethereum
    eth_balance = check_eth_balance(eth_address)
    print(Fore.GREEN + f"Ethereum Address: {eth_address}, Balance: {eth_balance} ETH")
    if eth_balance and eth_balance > 0.000000000001:
        with open("eth_data.txt", "w") as file:
            file.write(f"ETH Address: {eth_address}\nPrivate Key: {eth_private_key}\nBalance: {eth_balance} ETH\n")

    # Solana
    sol_balance = check_solana_balance(sol_address)
    print(Fore.CYAN + f"Solana Address: {sol_address}, Balance: {sol_balance} SOL")
    if sol_balance and sol_balance > 0.000000000001:
        with open("sol_data.txt", "w") as file:
            file.write(f"SOL Address: {sol_address}\nPrivate Key: {sol_private_key}\nBalance: {sol_balance} SOL\n")

    # Tron
    tron_balance = check_tron_balance(tron_address)
    print(Fore.YELLOW + f"Tron Address: {tron_address}, Balance: {tron_balance} TRX")
    if tron_balance and tron_balance > 0.000000000001:
        with open("tron_data.txt", "w") as file:
            file.write(f"TRX Address: {tron_address}\nPrivate Key: {tron_private_key}\nBalance: {tron_balance} TRX\n")

    # Delay to avoid rate limits
    time.sleep(1)