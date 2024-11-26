# Lab#2: File Transfer and Encryption
**Student ID**: 22110013  
**Name**: Nguyen Le Tung Chi  
**Course**: INSE33030E_02FIE

---
**Question 1**: 
Implement public-key based authentication step-by-step with openssl according the following scheme.

**Answer 1**:


#### Setup
Install the OpenSSL by : `sudo apt install openssl -y`
Set up 2 computer:
- **Alice** (server): IP 10.9.0.5  
- **Bob** (client): IP 10.9.0.6
Run `docker-compose up -d`
![image](https://github.com/user-attachments/assets/40254ed4-9c4a-4c99-96bd-f3c870c25ec1)
### Steps on the computer Alice

1. **Create a file**: On computer A, create a plaintext file `file.txt` with the following content:
    ```bash
    echo "Hello, this is a test file for Task 1." > file.txt
    ```
  ![image](https://github.com/user-attachments/assets/49ef6851-c0a1-45d9-be16-f75d68732070)

2. **Generate digits to ensure integrity and authenticity:**: Generate RSA key on the computer Bob :
   Create the private key
    ```bash
     openssl genrsa -out private.key 2048
    ```
    ![image](https://github.com/user-attachments/assets/4b921c9f-e4d2-46ad-b6f5-02e6e3ede210)

    - **`genrsa`**: used to generate an RSA private key. RSA is an asymmetric encryption algorithm widely used for data security and digital signatures.
    - **`-out private.key`**: specify the output file where the private key will be saved to a file named private.key
    - **`2048`**: The length of the key is 2048 bits
   
   Generate public key from private key
   ```bash
    openssl rsa -in private.key -pubout -out public.key
   ```
    - **`rsa`**: RSA key processing, including validation, format conversion, and key export..
    - **`-pubout`**: This flag tells OpenSSL to export the public key from the provided private key
    - **`-out public.key`**: SSpecify the output file where the public key will be saved to the public.key file.
    ![image](https://github.com/user-attachments/assets/3ad0c555-b2aa-4b17-ad8b-dd68c0d2555c)

    3. **Transfer PublicKey to Alice's computer


    ### At machine B (Receiving Side):
    
    Verify signature:
    ```bash
    Copy the code
    openssl dgst -sha256 -verify public.key -signature signature.bin file.txt
    ```
    Check checksum to ensure integrity:
    ```bash
    openssl dgst -sha256 file.txt
    ```
    Compare the checksum result received with the file file.sha256.
   ### 4.2 Encrypt the Text File 

    Alice encrypts the file txt use AES encryption with generated key:
    
    ```openssl enc -aes-256-cbc -in file.txt -out file.enc -pass file:/home/randompassword```
    - ```enc -aes-256-cbc```: Specifies AES encryption with CBC mode.
    - ```-in file.txt```: Input file to encrypt.
    - ```-out file.enc```: Output encrypted file.
    - ```-pass file:/home/randompassword```: Uses the symmetric key stored in randompassword.
    
    ### 4.3 Encrypt the Symmetric Key by RSA
    Alice encrypts the symmetric key using Bob’s public RSA key:
    
    ```openssl rsautl -encrypt -inkey public.key -pubin -in randompassword -out randompassword.encrypted```
    
    - ```rsautl -encrypt```: Encrypts data with RSA.
    - ```-inkey public.key```: Uses Bob’s public key.
    - ```-pubin```: Indicates the input is a public key.
    - ```-in randompassword```: The symmetric key to encrypt.
    - ```-out randompassword.encrypted```: Saves the encrypted symmetric key.
      
        # Task 2: Encrypting large message 
    Create a text file at least 56 bytes.
    **Question 1**:
    Encrypt the file with aes-256 cipher in CFB and OFB modes. How do you evaluate both cipher as far as error propagation and adjacent plaintext blocks are concerned. 
    **Answer 1**:
    1. **Create a text file**: Create a text file at least 56 bytes:
        ```bash
        echo "This is a test file for demonstrating AES-256 encryption in different modes." > large_message.txt
        ```
       **Steps to Encrypt**
    AES-256-CFB and AES-256-OFB Encryption:
    Generate AES-256 (256 bits = 64 hex characters) and IV (128 bits = 32 hex characters) keys.
    Use OpenSSL to generate these values:
    
    ```bash
    openssl rand -hex 32 > key.txt 
    openssl rand -hex 16 > iv.txt
    ```
    
    **Theoretical analysis:**
    
    ***CFB (Cipher Feedback Mode)***:
    
    - Plaintext blocks depend on the IV, key, and previous ciphertext block.
    - The error in the ciphertext will propagate, corrupting the failed block and subsequent blocks.
    
   ***OFB (Output Feedback Mode)***:
    
    - OFB generates an independent key sequence from the IV and key, then XORs it with the plaintext.
    - Errors in the ciphertext only affect the corresponding byte in the plaintext. There is no error propagation.
    This command does the following:
    **Question 2**:
    Modify the 8th byte of encrypted file in both modes (this emulates corrupted ciphertext).
    Decrypt corrupted file, watch the result and give your comment on Chaining dependencies and Error propagation criteria.
    
    **Answer 2**:



