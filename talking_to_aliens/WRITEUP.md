# talking_to_aliens - Writeup

We are given a file that contains a single line of digets.
There are 1679 digits in the file.
We assume that the file contains some kind of ASCII art that shows the flag.
As 1678 only has two prime factors, 23 and 73, we try to print the digits in multiple lines of 23 and 73 digits respectively.
As the digit 0 dominates the file, we assume that 0 is a space character, so we replace all 0s with spaces.

Printing 23 digits per row does not look like a meaningful message.
But when printing 73 digits per row, we see the flag.

```text
   44   44  5  5   3 2  2  77  2  2       22   55  4    5  5 222         
  4    4    5  5  3  2  2 7  7 2  2      2    5  5 4    5  5 2  2        
  4    4    5  5  3  2  2 7  7 2  2      2    5  5 4    5  5 2  2        
   44   44  5555 3    22  7  7 2  2       22  5  5 4    5  5 2  2        
     4    4 5  5  3     2 7  7 2  2         2 5  5 4    5  5 2  2        
     4    4 5  5  3     2 7  7 2  2         2 5  5 4     55  2  2        
   44   44  5  5   3  22   77   22  7777  22   55  4444  55  222  7777   
                                                                         
  3 3 3 3   3 33   3 33 3 3   33 33 33   33 33   3   33 3   3 3 3        
  33 3 33 3   3 3 3 3   33 3 3   3 3 33   33 33   3 3 3   3 3 3   33     
  33   3 3 33   3 3 3 3   33 3   3 33 33                                 
  3 33   3 3 3   33 3 3   3 3 33   33                        6           
  3 3 33   3 3 3 3   33 3   33 33   3 3 33   3 3 3   3 3 3   6      2    
                                             33            66666   222   
   44  222  5555  777     5 222   77   3                  6 666 6 22222  
  4  4 2  2 5    7        5 2  2 7  7   3                6  666  6 22222 
  4  4 2  2 5    7        5 2  2 7  7   3                   666 2   222  
  4444 222  5555 7        5 222  7  7    3                  6 6      2   
  4  4 2 2  5    7        5 2  2 7  7   3                   6 6          
  4  4 2  2 5    7        5 2  2 7  7   3                   6 6          
  4  4 2  2 5555  777     5 222   77   3                   66 66         
```

The flag is `SSH{YOU_SOLVD_ARECIBO}`

By the way: The middle part with the many 3s contains a morse code encoded message that reads

```
HALO MENSCH DU MSST TUHN WAS DU TUHN MUSST
```

Obviously, the aliens are not very good at speeking German.
