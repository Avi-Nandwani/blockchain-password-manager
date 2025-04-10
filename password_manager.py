import hashlib
import json
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


class Block:
    def __init__(self, index, timestamp, service_name, password_hash, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.service_name = service_name  # Added service name
        self.password_hash = password_hash
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_str = str(self.index) + self.timestamp + self.service_name + self.password_hash + self.previous_hash
        return hashlib.sha256(block_str.encode('utf-8')).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'service_name': self.service_name,
            'password_hash': self.password_hash,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }

    @staticmethod
    def from_dict(block_dict):
        return Block(
            block_dict['index'],
            block_dict['timestamp'],
            block_dict['service_name'],
            block_dict['password_hash'],
            block_dict['previous_hash']
        )


class Blockchain:
    def __init__(self, filename='blockchain.json'):
        self.chain = []
        self.filename = filename
        self.load_blockchain()

    def create_genesis_block(self):
        genesis_block = Block(0, str(time.time()), "genesis_block", "genesis_block", "0")
        self.chain.append(genesis_block)

    def add_block(self, service_name, password_hash):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), str(time.time()), service_name, password_hash, previous_block.hash)
        self.chain.append(new_block)
        self.save_blockchain()

    def display_chain(self):
        for block in self.chain:
            print(json.dumps(block.to_dict(), indent=4))

    def find_password(self, service_name):
        for block in self.chain:
            if block.service_name == service_name:
                return block.password_hash
        return None

    def load_blockchain(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                blockchain_data = json.load(f)
                self.chain = [Block.from_dict(block) for block in blockchain_data]
        else:
            self.create_genesis_block()

    def save_blockchain(self):
        with open(self.filename, 'w') as f:
            blockchain_data = [block.to_dict() for block in self.chain]
            json.dump(blockchain_data, f, indent=4)


def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()


def verify_password(stored_hash, input_password, salt):
    input_hash = hash_password(input_password, salt)
    return stored_hash == input_hash


def main():
    blockchain = Blockchain()

    while True:
        print("\nPassword Manager - Blockchain Version")
        print("1. Add a new password")
        print("2. View all stored passwords (hashed)")
        print("3. Retrieve a password")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service_name = input("Enter the name of the service (e.g. 'Facebook'): ")
            password = input("Enter your password: ")
            salt = input("Enter a salt for extra security (use a random string): ")

            password_hash = hash_password(password, salt)
            blockchain.add_block(service_name, password_hash)

            print(f"Password for {service_name} has been securely added.\n")

        elif choice == '2':
            print("Displaying all stored password hashes (not actual passwords for security):\n")
            blockchain.display_chain()

        elif choice == '3':
            service_name = input("Enter the service name for which you want to retrieve the password: ")
            salt = input("Enter the salt you used to store the password: ")
            
            stored_hash = blockchain.find_password(service_name)

            if stored_hash:
                password_attempt = input("Enter your password to verify: ")

                if verify_password(stored_hash, password_attempt, salt):
                    print(f"Password for {service_name} is correct!")
                else:
                    print("Incorrect password!")
            else:
                print(f"No password found for service: {service_name}")

        elif choice == '4':
            print("Exiting the password manager.")
            break

        else:
            print("Invalid choice. Please choose again.")


if __name__ == "__main__":
    main()
