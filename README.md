# Cryptography - University of Maryland, College Park (Jonathan Katz) - Coursera

Solutions of weekly assignments to practice Go.

## Week 1: [Breaking the Vigenere cipher][w1]

Write a program that allows you to "crack" ciphertexts generated using a Vigenere-like cipher, where byte-wise XOR is used instead of addition modulo 26.

## Week 2: [Breaking the One Time Pad][w2]

Below are 7 ciphertexts, each of which was generated by encrypting some 31-character ASCII plaintext with the one-time pad using the same key (code for the encryption program used is given below).
Decrypt them and recover all 7 plaintexts, each of which is a grammatically correct English sentence.

## Week 3: [Padding Oracle Attacks][w3]

In this assignment, you must decrypt a challenge ciphertext generated using AES in CBC-mode with PKCS #7 padding. To do so, you will be given access to a server that will decrypt any ciphertexts you send it (using the same key that was used to generate the challenge ciphertext)...but that will only tell you whether or not decryption results in an error!

## Week 4: [CBC-MAC Attacks][w4]

In this assignment, you will implement an attack against basic CBC-MAC showing that basic CBC-MAC is not secure when used to authenticate/verify messages of different lengths. Here, you will be given the ability to obtain tags (with respect to some unknown key) for any 2-block (32-byte) messages of your choice; your goal is to forge a valid tag (with respect to the same key) on the 4-block (64-byte) message "I, the server, hereby agree that I will pay $100 to this student." (Omit the final period and the quotation marks. You should verify that the message contains exactly 64 ASCII characters.) You will also be given access to a verification routine that you can use to verify your solution.


[w1]: week_01-vigenere/
[w2]: week_02-many_time_pad/
[w3]: week_03-padding_oracle/
[w4]: week_04-cbc_mac/
