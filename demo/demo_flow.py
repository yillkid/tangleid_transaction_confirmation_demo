import M2Crypto
import M2Crypto.BN as BN
import os

def generate_keypair_as_pem(key_len, exponent):
    def empty_callback():
        pass

    rsa = M2Crypto.RSA.gen_key(key_len, exponent, empty_callback)
    # Get RSA Public Key in PEM format
    buf = M2Crypto.BIO.MemoryBuffer('')
    rsa.save_pub_key_bio(buf)
    public_key = buf.getvalue()

    # Get Private Key in PEM format
    buf = M2Crypto.BIO.MemoryBuffer('')
    rsa.save_key_bio(buf, None)
    private_key = buf.getvalue() # RSA Private Key
    
    return (public_key, private_key)

def get_data_digest(data):
    msg_digest = M2Crypto.EVP.MessageDigest('sha256')
    msg_digest.update (data)
    digest =  msg_digest.digest()
    return digest

def generate_secure_msg(A_private_key, B_public_key, message):
    padding = M2Crypto.RSA.pkcs1_oaep_padding
    buf = M2Crypto.BIO.MemoryBuffer('')
    buf.write(B_public_key)
    rsa1 = M2Crypto.RSA.load_pub_key_bio(buf)
    cipher_message = rsa1.public_encrypt(message, padding)
    # Use A's private key to sign the 'cipher_message'
    digest1 = get_data_digest(cipher_message)
    rsa2 = M2Crypto.RSA.load_key_string(A_private_key)
    signature = rsa2.sign(digest1, 'sha256')
    return cipher_message, signature

def read_secure_msg(A_public_key, B_private_key, cipher_message, signature):
    try:
        # Use A's public key to verify 'signature'
        buf = M2Crypto.BIO.MemoryBuffer('')
        buf.write(A_public_key)
        rsa3 = M2Crypto.RSA.load_pub_key_bio(buf)                
        # Verify
        digest2 = get_data_digest(cipher_message)
        rsa3.verify(digest2, signature, 'sha256')
        # Use B's private key to decrypt 'cipher_message'
        rsa4 = M2Crypto.RSA.load_key_string(B_private_key)        
        padding = M2Crypto.RSA.pkcs1_oaep_padding
        plaintext_message = rsa4.private_decrypt(cipher_message, padding)
        return plaintext_message
    except Exception as err:        
        print 'Verify Fail:%r'% err
        raise 

def msg_introduction():
    os.system('clear') 
    print "This is a demonstration about how to a transaction confirmation of a customer, a merchant and a bank."
    print "Work flow:"
    print "  1. Customer issue a transaction with: Chaper(Order info.), Signature, UUID"
    print "  2. Merchant receive the transaction, verify and decript it"
    print "  3. Call banker API when the transactio verified"
    print "\n"
    print "Refer this graphic for detail: https://github.com/yillkid/tangleid_transaction_confirmation_example/raw/master/img/C2BPaymentFlow.png"
    print "-------------------------------------------------------------"
    raw_input("Press Enter to continue...")

def msg_a_gen_keys():
    os.system('clear') 
    print "Identity Customer:"
    print "\n"
    print "-------------------------------------------------------------"
    print "public key (C):" + A_pub_key
    print "private key (C):" + A_priv_key
    print "-------------------------------------------------------------"
    raw_input("Press Enter to continue...")

def msg_b_gen_keys():
    os.system('clear') 
    print "Identity Merchant:"
    print "\n"
    print "-------------------------------------------------------------"
    print "public key (M):" + B_pub_key
    print "private key (M):" + B_priv_key
    print "-------------------------------------------------------------"
    raw_input("Press Enter to continue...")

def msg_transaction_msg(transaction_msg): 
    os.system('clear') 
    print "Customer issue a transaction to Merchant:"
    print "-------------------------------------------------------------"
    print transaction_msg
    print "-------------------------------------------------------------"
    raw_input("Press Enter to continue...")

def msg_sender_behaver(cipher_msg, signature):
    os.system('clear') 
    print "-------------------------------------------------------------"
    print "---------     ----------------    ---------------------- " 
    print "| Chaper | =  | Merchant's PK | + | Transaction content |"
    print "---------     ----------------    ---------------------- "
    print "\n"
    print "------------     ---------    ---------------- " 
    print "| Signature | =  | Chaper | + | Customer's PK |"
    print "------------     ---------    ---------------- "
    print "-------------------------------------------------------------"
    print "Transaction content: Chapter, Signature"
    print "IOTA Transaction TAG: Merchant's UUID"
    print "IOTA Transaction Message: Chaper, Signature"
    print "-------------------------------------------------------------"
    print "Therefore"
    print "Customer chaper: " + cipher_msg
    print "\n"
    print "Customer signature: " + signature
    print "-------------------------------------------------------------"
    print "-----------                                      ---------- "
    print "| Customer | -- (Issue a IOTA transaction) -->  | Merchant |"
    print "-----------                                      ---------- "
    print "IOTA Transaction Message Field:"
    print cipher_msg + "," + signature

    raw_input("Press Enter to continue...")

def msg_receiver_behaver(A_pub_key, signature, plain_text):
    os.system('clear') 
    print "-------------------------------------------------------------"
    print "-------------     -------------------     --------- " 
    print "| Plain Text | =  | Merchant's PriKey | + | Chaper |"
    print "-------------     -------------------     --------- "
    print "\n"
    print "---------     ------------    ---------------- " 
    print "| Verify | =  | Signature | + | Customer's PK |"
    print "---------     ------------    ---------------- "
    print "-------------------------------------------------------------"
    print "Plain Text: " + plain_text
    print "-------------------------------------------------------------"

    raw_input("END.")

if __name__ == '__main__':
    keylen = 1024         # 1024 bits
    exponent = 65537
    transaction_msg = '{"order_id":"12345", "order_count":"2", "signature":"", "UUID":"DJIE9DN"}'
    
    padding = M2Crypto.RSA.pkcs1_oaep_padding
 
    msg_introduction() 
    
    # Generate RSA key-pair in PEM files for public key and private key 
    A_pub_key, A_priv_key = generate_keypair_as_pem(keylen, exponent)
    msg_a_gen_keys()
 
    # Generate RSA key-pair in PEM files for public key and private key 
    B_pub_key, B_priv_key = generate_keypair_as_pem(keylen, exponent)
    msg_b_gen_keys()

    # A is sender, B is receiver
    msg = transaction_msg
    msg_transaction_msg(msg)

    # Sender's behavior
    cipher_msg, signature = generate_secure_msg(A_priv_key, B_pub_key, msg)
    msg_sender_behaver(cipher_msg, signature)
    
    # Receiver's behavior
    plain_text = read_secure_msg(A_pub_key, B_priv_key, cipher_msg, signature)
    msg_receiver_behaver(A_pub_key, signature, plain_text)
