# SDES

SDES.java README

Jessup Barrueco

The Simplified DES (S-DES) encryption algorithm takes an 8-bit block of plaintext (example: 00101000) and a 10-bit key (example: 1100011110) from the command line and produces an 8-bit block of ciphertext as output. Similarly, the S-DES Decryption algorithm takes that 8-bit block of ciphertext and the same 10-bit key as input, producing the original 8-bit block of plaintext.

To compile and run this program, from the terminal execute the following commands:
> javac SDES.java


> java SDES

The program will ask the user to input an 8-bit block of plaintext followed by a 10-bit key. Then, the encryption and decryption algorithms are performed.

The Encryption algorithm relies on 5 functions: an initial permutation (IP); a function FK which depends on key input, and involves permutation, substitution, and the use of a function F which maps 4-bit strings to 4-bit strings; a switching function SW which performs a simple permutation, switching the two 4-bit Left and Right halves of the data; then, the function FK is performed again; and the final function is an inverse of the initial permutation function (IP^(-1)). Combining permutation with substitution results in an algorithm that is more complex, increasing the difficulty of cryptanalysis.

The function FK takes the Left and Right 4-bits of the plaintext after its initial permutation, and a specified subkey (K1, K2). It returns 8-bit output. 
FK requires the use of a mapping function F, which takes in the 4bit Right Half of plaintext with an 8-bit subkey, producing a 4-bit output. First, F performs an expansion/permutation where the output is XOR'd with the subkey. The result is then split into two 4-bit halves. The algorithm defines and constructs two S-boxes S0 and S1. Then, the Left 4-bits are processed through S0, producing a 2-bit output. The Right 4-bits are then processed through S1, producing another 2-bit output. The S-Boxes operate by treating the first and fourth input bits as a 2-bit number specifying a row in the S-box; the second and third input bits specify a column. The entry in that row and column, converted to base 2, is the 2-bit output. The 4-bits produced by S0 and S1 are then permuted via permutation P4. The result of this permutation is the output of the function F.

Key Generation is vital to this algorithm, as S-DES depends on the use of a 10-bit key shared between sender and receiver. From this key, two 8-bit subkeys (K1, K2) are generated for use in encryption and decryption. To produce the subkeys, the originally inputted key first undergoes a permutation P10. Then, a circular left shift is performed separately on the Left 5 and Right 5 bits of the key. Next, another permutation P8 is performed which permutes 8 out of the 10 bits of the key, resulting in the first subkey K1. To generate K2, we perform another circular left shift on the pair of 5-bit strings produced by the first left shift function. Finally, permutation P8 is performed on this output, resulting in the second subkey K2.

The SDES algorithm is vulnerable; a brute-force attack is quite feasible since with a 10-bit key, there are only 2^10 = 1024 possibilities. An attacker can exhaustively try each possibility, given a ciphertext. The more robust algorithm, DES, operates on 64-bit blocks of input, using a 56-bit key, from which 16 48-bit subkeys are generated. Though exhaustive attacks against DES are also feasible, they require substantially more computing power than for SDES.
