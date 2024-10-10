## "conjecture" - PRK backdoor for HKDF-wise systems

### How to exploit?


- Let's set some variables first:

- let $P$ be the PRK, a byte array.

- let $P[15]$ be index 15 of $P$.
- $M$ will be our mask, where we compute it as $P[len(P)-1] \mod 16$ .
- $K$ is $0x42$, our backdoor constant
- $N = KM \ ROT \ 3$, where we rotate N by 3 bits by a bitwise left shift.
- $P_{modif} [15]$ is our modified byte

Thus, we can reduce our backdoor's operation to this expression:

$P_{modif} [15] = P[15] \oplus  ((K \cdot M) ≪ 3)$


alternatively:

$P_{modif} [15] = P[15] \text{ XOR }  ((K \cdot M) ≪ 3)$

Where $≪$ denotes a leftwards bitwise 3-bit shift.

In pseudocode:

<img src="https://files.catbox.moe/y51u7f.png">


