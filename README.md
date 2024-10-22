# Lab Report: Diffie-Hellman Key Exchange and RSA Encryption/Decryption

**Authors:**  
Michalis Lamprakis - 2020030077  
Christos Dimas     - 2021030183

This `README.md` serves as a lab report for the first exercise, explaining the code implementation of two cryptographic algorithms: Diffie-Hellman Key Exchange and RSA (Rivest–Shamir–Adleman) encryption/decryption.

---

## Diffie-Hellman Key Exchange

The Diffie-Hellman Key Exchange is implemented as follows:

1. **Initialization**:  
   In the main program, all variables are initialized using the `mpz_init` function from the `gmp.h` library.
   
2. **Input Handling**:  
   The program takes arguments from the user, using specific command-line commands to specify the input values.
   
3. **Calculation**:  
   The program calculates the necessary equations for the Diffie-Hellman method.

4. **Output**:  
   The result is written to a file, containing three numbers:
   - **Public Key A**
   - **Public Key B**
   - **Shared Key**

---

## RSA (Rivest–Shamir–Adleman) Algorithm

### Key Generation Process:

1. **Step 1**:  
   The user provides two prime numbers, `p` and `q`. With the `-g` argument, the program also takes the desired key length.

2. **Step 2**:  
   The program checks if the numbers are prime using the `mpz_probab_prime_p` function from the `gmp.h` library. If the function returns `2`, the number is considered prime. If the numbers are not prime, the program selects another random number within the range.

3. **Step 3**:  
   Once valid primes are chosen, the program calculates `n` using the `mpz_mul` function.

4. **Step 4**:  
   It calculates `λ(n)` using `mpz_sub_ui` and `mpz_mul` functions.

5. **Step 5**:  
   The `e` value (public exponent) is initialized and calculated according to the equation using functions from the same library.

6. **Step 6**:  
   The program calculates `d` (private exponent) using the `mpz_invert` function.

7. **Step 7 & Step 8**:  
   Two key files are generated:
   - `public.key` (containing `n` and `e`)
   - `private.key` (containing `n` and `d`)

---

### Encryption Process:

- The input file for encryption will be a plaintext file.
- The output will be a binary file that contains long integer values generated during the encryption process. The binary format helps store long variables without truncation.

---

### Decryption Process:

- The input file for decryption will be a binary file.  
- Using the public key, the program will generate a decrypted plaintext file, saved with a user-specified filename.

---

## Time Comparison

### `-a` Argument

The `-a` argument is used for time comparison and takes an output `.txt` file as an argument (specified by the user), where the time results (in seconds) are stored.

1. The program generates new public and private keys for three different key lengths.
2. Using the `clock` function from the library, it calculates the time taken for each function call.
3. The functions used for this comparison are the same as those used in the encryption/decryption process, but with fixed arguments (for input, output, and key files).

---

### Conclusion

This lab report details the implementation of two cryptographic algorithms: Diffie-Hellman and RSA. It explains the key generation, encryption, decryption processes, and time comparison between different key lengths in RSA encryption.
