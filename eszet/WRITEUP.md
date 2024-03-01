# eszet - Writeup

We are given the website of the "Eszet Enjoyer Society" which expects a password for login.
Inspecting the source code, we find a comment that says "I love Eszet" but written with emojis.

Googling for 'unicode eye', we learn that the eye emoji is `U+1F441` which looks like so: `👁`.
The unicode for 'love' is `U-2661` and looks like so: `♡`.
Last but not least, we need an emoji for Eszett. Trying the normal german lowercase `ß` gives us the hint that we are close but that the Eszett was not the right one. So we google for 'unicode eszett emoji' and find that there is a capital Eszett `U+1E9E` which looks like so: `ẞ`.

Typing in the password `👁♡ẞ` gives us the flag.
