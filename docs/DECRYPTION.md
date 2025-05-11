Here's the decryption flow:
Initiation: A user (let's say User A, but it could be any authorized party, or the system itself orchestrating this) wants to decrypt the file.
Share Contribution Phase (The "Unlock" Attempt):
The system identifies that k shares are needed.
It requests (or users proactively provide) their encrypted shares.
User A provides Encrypted_Share_A. User A uses their private key to decrypt Encrypted_Share_A, successfully recovering the plaintext SSS share point (1, Y<sub>1</sub>).
User B provides Encrypted_Share_B. User B uses their private key to decrypt Encrypted_Share_B, successfully recovering the plaintext SSS share point (2, Y<sub>2</sub>).
(Optional) User C might provide Encrypted_Share_C. User C uses their private key to decrypt Encrypted_Share_C, recovering (3, Y<sub>3</sub>).
Collection and Verification:
The system (or the user initiating decryption, like admin1 in your logs) collects these decrypted plaintext SSS share points.
In your current log scenario:
admin1 attempts to decrypt an encrypted share they possess (let's say it was originally Share_Point_1, so admin1 is User A). They succeed. Result: (1, Y<sub>1</sub>).
admin1 then attempts to decrypt another encrypted share they have access to from the database (let's say this was Encrypted_Share_B, originally intended for User B). This fails because admin1's private key doesn't match User B's public key used for encryption.
The system notes: 1 successful share, 1 failed share.
Threshold Check:
The system counts how many unique, successfully decrypted plaintext SSS share points it has.
If this count is >= k (the threshold), proceed to step 5.
If this count is < k, the FEK cannot be reconstructed. The file remains locked. The user is informed they need more valid shares. (This is what's happening in your logs: 1 successful share < threshold of 2).
FEK Reconstruction:
If the threshold is met (e.g., we have (1, Y<sub>1</sub>) and (2, Y<sub>2</sub>) because k=2), these plaintext SSS share points are fed into the Lagrange interpolation algorithm (reconstruct_secret in your shamir_utils.py).
This reconstructs the original FEK.
File Decryption:
The reconstructed FEK is used to decrypt the actual file data using AES-GCM.
The file is now "unlocked" and accessible.
"Can the file be unlocked after decryption of any of the 3 shares?"
No, not any single one if the threshold k > 1. It can be unlocked after decryption of any k distinct and valid SSS share points.
If k=2 and n=3:
Successful decryption of (Share_Point_1 by User A) AND (Share_Point_2 by User B) -> Unlock.
Successful decryption of (Share_Point_1 by User A) AND (Share_Point_3 by User C) -> Unlock.
Successful decryption of (Share_Point_2 by User B) AND (Share_Point_3 by User C) -> Unlock.
Only successful decryption of (Share_Point_1 by User A) -> File remains locked.