from main import *

block = BlockChain()

#generate first account/create genesis block/first account mining
address, private = block.generate_address()
block.start()

#Create First Transaction
new_transaction = block.initialize_transaction(address, 'test', 1, 100, 'Test_Generate_transaction')
if new_transaction:
    signature = block.sign_transaction(new_transaction, private) #signed transaction
    block.add_transaction(new_transaction, signature)  #add transaction to pending_transactions

block.mine_block(address)
block.verify_blockchain()

    
#Test if someone tamper the transaction, verifying will fail 
print("***************************\nInsert fake transaction.\n***************************")

fake_transaction = Transaction('test', address, 100, 1, 'Test_tamper')    
block.chain[1].transactions.append(fake_transaction)
block.mine_block(address)

block.verify_blockchain()

for i in range(len(block.chain)):
    print(f'====Block {i}====\nPrevious Hash : {block.chain[i].previous_hash}\nNonce : {block.chain[i].nonce}\nHash : {block.chain[i].hash}\nTransaction Number : {len(block.chain[i].transactions)}')
    if len(block.chain[i].transactions):
        for j in range(len(block.chain[i].transactions)):
            print(f'Transaction : {block.transaction_to_string(block.chain[i].transactions[j])}\n')
