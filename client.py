import sys
import socket
import threading
import rsa
import pickle
import time

###############################################################
#                                                             #
#   Things that client can do:                                #
#    1. Generate their own address and private key            #
#    2. Generate Transaction(No need to check validation)     #
#       - need to provide                                     #
#           - address                                         #
#           - private key (in order to sign the transaction)  #
#           - receiver                                        #
#           - amount                                          #
#           - fee                                             #
#           - comments                                        #
#       - will get                                            #
#           - Transaction Sucess/Fail                         #
#     3. Get their account balance                            #
#       - need to provide their address                       #
#       - will get their balance                              #
#                                                             #
#   Things that client should do:                             #
#    1. Keep listening to server                              # 
#                                                             #
###############################################################

#listen to server
def handle_receive():
    while(True):
        response = client.recv(4096)
        if response:
            print(f'[*] Message From Server : {response.decode()}')

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message

#generate keys
def generate_address():
    (public_key, private_key) = rsa.newkeys(512)
    public_key = public_key.save_pkcs1()
    private_key = private_key.save_pkcs1()
    public_key = str(public_key).replace('\\n', '')
    public_key = public_key.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')          
    public_key = public_key.replace("-----END RSA PUBLIC KEY-----'", '')
    public_key = public_key.replace(' ', '')
    private_key = str(private_key).replace('\\n', '')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    private_key = private_key.replace(' ', '')
    return public_key, private_key

#in order to send transaction
def transaction_to_string(transaction):
    transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
    return str(transaction_dict)

#initialize transaction
def initialize_transaction(sender, receiver, amounts, fee, message):
    new_transaction = Transaction(sender, receiver, amounts, fee, message)
    return new_transaction

#sign transaction
def sign_transaction(transaction, private_key):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n' + private_key + '\n-----END RSA PRIVATE KEY-----\n'
    private_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    transaction_str = transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode('utf-8'), private_pkcs, 'SHA-1')
    #Usage : rsa.sign(signed_message, private_key, method_of_hash)
    return signature
    
if __name__ == "__main__":
    target_host = "127.0.0.1"
    target_port = int(sys.argv[1])
    client =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    
    receive_handler = threading.Thread(target = handle_receive, args = ())
    receive_handler.start()

    command_dict = {
            '1' : 'generate_address',
            '2' : 'get_balance',
            '3' : 'transaction'
        }

    while(True):
        print("Command List:")
        print("1. Generate Address")
        print("2. Get Balance")
        print("3. Transaction")
        command = input("Input number to execute : ")
        if str(command) not in command_dict.keys():
            print("Invalid Command!")
            continue
        else:
            message = {"request" : command_dict[str(command)]}
            if command_dict[str(command)] == "generate_address":
                address, private_key = generate_address()
                print('This is your address : ', address)
                print('Here\'s Your Private Key : ',private_key)
                print('Keep it carefully!!')
            elif command_dict[str(command)] == "get_balance":
                address = input("Address : ")
                message["address"] = address
                client.send(pickle.dumps(message)) #dumps(data): save the data to string

            elif command_dict[str(command)] == "transaction":   
                print("Please fill these information.")
                address = input("Address : ")
                privare_key = input("Private Key : ")
                receiver = input("Receiver : ")
                amount = int(input("Amount : "))
                fee = int(input("Fee : "))
                comment = input("Comment : ")
                new_transaction = initialize_transaction(address, receiver, amount, fee, comment)
                signature = sign_transaction(new_transaction, private_key)
                message["data"] = new_transaction
                message["signature"] = signature
                client.send(pickle.dumps(message))
            else:
                print("Invalid Command.")
            time.sleep(1)


