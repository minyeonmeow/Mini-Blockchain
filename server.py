import hashlib
import time
import rsa
import sys
import threading
import socket
import pickle

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message


class Block:
    def __init__(self, previous_hash, difficulty, miner, miner_rewards):
        self.previous_hash = previous_hash
        self.hash = ''
        self.difficulty = difficulty
        self.nonce = 0
        self.timestamp = int(time.time())
        self.transactions = []
        self.miner = miner
        self.miner_rewards = miner_rewards


class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 10
        self.difficulty = 1
        self.block_time = 30
        self.miner_rewards = 10
        self.block_limitation = 32
        self.chain = []
        self.pending_transactions = []

        #Prepare for P2P
        self.socket_host = '127.0.0.1'
        self.socket_port = int(sys.argv[1])
        self.start_socket_server()

    def create_genesis_block(self):
        print(f"+++++++++++++++++++++++++++++++\n+  Creating Genesis Block...  +\n+++++++++++++++++++++++++++++++")
        new_block = Block('Hello World!', self.difficulty, 'minyeon', self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)
        print(f'++++++++++++++++++\n+  {new_block.previous_hash}  +\n++++++++++++++++++')

    
    def initialize_transaction(self, sender, receiver, amounts, fee, message):
        new_transaction = Transaction(sender, receiver, amounts, fee, message)
        return new_transaction

    def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_dict)

    def get_transactions_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash
                + str(block.timestamp)
                + self.get_transactions_string(block)
                + str(nonce)
            ).encode("utf-8")
        )
        h = s.hexdigest()
        return h

    def add_transaction_to_block(self, block):
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)
        if len(self.pending_transactions) > self.block_limitation:
            transcation_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transcation_accepted


    def mine_block(self, miner):
        start = time.process_time()

        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)

        self.add_transaction_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        time_consumed = round(time.process_time() - start, 5)
        print(f'===============================\nHash Found : {new_block.hash}\nNonce : {new_block.nonce}\nDifficulty : {self.difficulty}\nTime Cost : {time_consumed}s\n===============================')
        self.chain.append(new_block)

    def adjust_difficulty(self):
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            if average_time_consumed > self.block_time:
                print(f"===============================\nAverage block time : {average_time_consumed}s\nLow Down Difficulty\n===============================")
                self.difficulty -= 1
            else:
                print(f"===============================\nAverage block time : {average_time_consumed}s\nHigh Up Difficulty\n===============================")
                self.difficulty += 1

    def get_balance(self, account):
        balance = 0
        for block in self.chain:
            miner = False
            if block.miner == account:
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:
                if miner:
                    balance += transaction.fee
                if transaction.sender == account:
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:
                    balance += transaction.amounts
        return balance

    def verify_blockchain(self):
        previous_hash = ''
        for idx,block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:
                print(f"===========================\n+  Error:Hash not match!  +\n===========================")
                return False
            elif previous_hash != block.previous_hash and idx:
                print(f"====================================\n+  Error:Previous Hash not match!  +\n====================================")
                return False
            previous_hash = block.hash
        print(f"==================\n+  Hash correct!  +\n===================")
        return True

    #generate Public/Privite Keys
    def generate_address(self):
        (public_key, private_key) = rsa.newkeys(512)
        public_key = public_key.save_pkcs1()
        private_key = private_key.save_pkcs1()
        public_key = str(public_key).replace('\\n','')
        public_key = public_key.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        public_key = public_key.replace("-----END RSA PUBLIC KEY-----'", '')
        public_key = public_key.replace(' ', '')
        private_key = str(private_key).replace('\\n','')
        private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
        private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
        private_key = private_key.replace(' ', '')
        return public_key, private_key
        
        
    #generate transaction by verify signature
    def add_transaction(self, transaction, signature):
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            print(f"==========================\n+  Balance Not Enough!!  +\n==========================")
            return False, "Balance Not Enough"
        try:
            rsa.verify(transaction_str.encode('utf-8'), signature, public_pkcs) #verify signature by using public key to decrypt the signature
            # means that the signature is signed by the public key's owner
            # rsa.verify(message, signature, pubkey) -> return true if valid
            print(f"=======================\n+  Authorize Sucess!  +\n=======================")
            self.pending_transactions.append(transaction)
            return True, "Authorize Sucess!"
        except Exception:
            print(f"================================\n+  Signature Authorize Fail!!  +\n================================")
            return False, "Signature Authorize Fail!"


    def start(self):
    
        #Use by Test start(self, address)    
        #address, private = self.generate_address()  #generate keys
        #self.create_genesis_block()
        #while(address):
        #    while(len(self.chain)<15):
        #        self.mine_block(address)
        #        self.adjust_difficulty()
        #    break   

        address, private = self.generate_address()
        print(f"=========================\nMiner Address : {address}\nMiner Private : {private}\n=========================")
        self.create_genesis_block()
        while(True):
            self.mine_block(address)
            self.adjust_difficulty()

    def start_socket_server(self):
        t = threading.Thread(target = self.wait_for_socket_connection)
        t.start()

    def wait_for_socket_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # AF_INET = Using IPv4 / AF_INET6 = Using IPv6
        # SOCK_STREAM = Using TCP / SOCK_DGRAM = Using UDP
            s.bind((self.socket_host, self.socket_port))
            s.listen()
            while(True):
                conn, address = s.accept() #accept new connection

                client_handler = threading.Thread(
                        target = self.receive_socket_message,
                        args=(conn, address)
                )
                client_handler.start()

    def receive_socket_message(self, connection, address):
        with connection:
            print(f'**************\nConnected by {address}\n**************')
            while(True):
                message = connection.recv(1024)
                print(f'Received : {message}')
                try:
                    parsed_message = pickle.loads(message)
                except Exception:
                    print(f'{message} cannot be parsed!!')
                if message:
                    if parsed_message["request"] == "get_balance":
                        print("=========================\nStart Getting Balance...=========================")
                        address = parsed_message["address"]
                        balance = self.get_balance(address)
                        response = {
                                "address" : address,
                                "balance" : balance}
                    elif parsed_message["request"] == "transaction":
                        print("=========================\nTransaction Creating...========================")
                        new_transaction = parsed_message["data"]
                        result, result_message = self.add_transaction(
                            new_transaction, parsed_message["signature"])
                        response = {
                                "result" : result,
                                "result_message" : result_message}
                    else:
                        response = {"message" : "Unknown Command"}
                    response_bytes = str(response).encode('utf-8')
                    connection.sendall(response_bytes)

if __name__ == "__main__" :
    block = BlockChain()
    block.start()
