# clack_clack - Writeup

We are given a pcapng file with USB traffic between the host and a single usb device.
Because the device sends a lot of interrupts, we can assume that it is a [Human Inderface Device (HID)](https://www.usb.org/hid).
When we look at the payloads of the interrupts and compare them with the HID Usage Tables, we see that the device is a keyboard.
We now have to extract the keystrokes from the pcapng file to learn what the attacker typed on the keyboard.
Reading the typed text reveals that the attacker created a new user `phantom` and deleted the bash history afterwards.
The user is created by adding entries to `/etc/passwd` and `/etc/shadow`.
But instead of a password hash, the attacker placed a flag in the `/etc/shadow` file.

