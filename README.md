# "Enabling Practical Privacy-Preserving Lawful Interception in 5G SA Core using Differential Obliviousness and Lattice-Based Homomorphic Encryption"

## why dp cannot work
https://eprint.iacr.org/2019/384.pdf Yeo and Persiano prove a lower bound on the operations you need to perform for
dp-pir, which are again expected to be O(N). Indeed a paper from https://www.usenix.org/system/files/sec22-albab.pdf achieves
differential obliviousness in the access patterns by adding Laplacian Noise to the access patterns hinstogram with magnitude O(N)...
their setting is best optimized for batching multiple queries.