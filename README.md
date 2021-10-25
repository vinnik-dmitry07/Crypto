## Benchmark

Method   | AES 1* | AES 2 | Kalyna (mine) | Kalyna 1 | Kalyna 2 | RC4  | Salsa20
---      | ---    |  ---  | ---           | ---      | ---      | ---  | ---
Hours/Gb | 5.4    | 29    | 10            | 120      | 290      | 0.47 | 0.0064

> \* ECB ~= CBC ~= PCBC ~= CFB ~= OFB ~= CTR

AES 2 - http://anh.cs.luc.edu/331/code/aes.py

Kalyna 1 - https://github.com/bre30kra69cs/KalinaPy

Kalyna 2 - https://github.com/trident-10/kalyna_cipher/


## Collision report

The number of random strings to receive the same hash:

String length \ Method   | SHA256 | Kupyna
---                      | ---    |  ---  
2                        | 152    | 191    
3                        | 457    | 891    
4                        | 15951  | 17605  
5                        | 175081 | 38576
