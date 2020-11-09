import pickle
import time 

from client import *


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
            address, private_key = "generate_address"
            print(f'This is your address : {address}')
            print(f'Here\'s Your Private Key : {private_key}\nKeep it carefully!!')
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

