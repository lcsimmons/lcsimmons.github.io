+++
title = "MetaCTF 2021"
date = 2021-12-18
description = "I competed in MetaCTF2021 on the team ret3rev back in December 2021."
+++

<center>

## Reverse Engineering

</center>

### Source Code Shipping

> *Ever wondered what was in those absolutely massive desktop apps such as Slack, Discord, and other apps built using Electron JS? Well we've created a small Electron-based app with a flag embedded in its source code for your perusal.*
> 
> *You don't need to install or run the app to get the flag.*

In order to get to the app's source code, we first need to get to the app's .asar file. I ran binwalk on Setup.exe and after extracting, I navigated to the resources folder where I found app.asar.

Before unpacking anything, I made a folder for the sourcecode.

Then, I ran this to unpack the .asar

```
npx asar extract app.asar sourcecode
```

I took a look at what's inside app.js

```javascript
// THE FL@G is right below this message!!
let f = "TWV0YUNURnt5b3VfY29tcGxldGVkX0FfU2VhcmNoX0FuZF9SZXNjdWVfdGhlX2ZsYWdfbWlzc2lvbn0=" 
```

*base64 time*

```
echo TWV0YUNURnt5b3VfY29tcGxldGVkX0FfU2VhcmNoX0FuZF9SZXNjdWVfdGhlX2ZsYWdfbWlzc2lvbn0= | base64 -d
```

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">MetaCTF{you_completed_A_Search_And_Rescue_the_flag_mission}</p>
</details>

___

### Revvy Chevvy

> *1 Flag, 2 Flag, Red Flag, Blue Flag. Encrypting flags is as easy as making a rhyme*

We are given `chall`. I opened it in Ghidra and navigated to `entry`. I clicked on the first argument of `__libc_start_main()` to get to our main function. 

```cpp
int main(void)

{
  char cVar1;
  int iVar2;
  char *userinput;
  size_t sVar3;
  long counter;
  long in_FS_OFFSET;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  __printf_chk(1,"What\'s the flag? ");
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  userinput = fgets((char *)&local_68,0x40,stdin);
  if (userinput == (char *)0x0) {
    puts("no!!");
    iVar2 = 1;
  }
  else {
    sVar3 = strcspn((char *)&local_68,"\n");
    *(undefined *)((long)&local_68 + sVar3) = 0;
    counter = 0;
    do {
      cVar1 = FUN_001011e9();
      *(byte *)((long)&local_68 + counter) =
           *(byte *)((long)&local_68 + counter) ^ cVar1 + (char)counter;
      counter = counter + 1;
    } while (counter != 0x40);
    iVar2 = memcmp(&local_68,PTR_s_t_N_Gd_-_Z_\_;0o_@_|W_v/_W_O_o_y_00104010,0x40);
    if (iVar2 == 0) {
      puts("You got it!");
    }
    else {
      puts("That\'s not it...");
      iVar2 = 1;
    }
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

After viewing this, I figured that we needed our user input, `local_68`, to match whatever is stored in `PTR_s_t_N_Gd_-_Z_\_;0o_@_|W_v/_W_O_o_y_00104010`, and we needed to decrypt what is stored in memory. 

I first got the value of our encyrpted flag through clicking the pointer that we memory compare to `local_68`, clicking on what that is pointing too, then copying it as a python list.

```python 
[ 0x74, 0x1a, 0x95, 0x4e, 0xba, 0xdb, 0x47, 0x64, 0x09, 0x2d, 0xd1, 0xbf, 0x8a, 0x9d, 0xde, 0x5a, 0xd7, 0x5c, 0x93, 0x16, 0x09, 0x3b, 0x30, 0x6f, 0x97, 0x40, 0xd0, 0x7c, 0x57, 0xdb, 0xde, 0x0c, 0x09, 0xa0, 0x84, 0x9b, 0x8a, 0x76, 0x2f, 0xb1, 0x57, 0xa2, 0xe1, 0x4f, 0xb9, 0x6f, 0x81, 0xbf, 0xb9, 0xbf, 0xe1, 0xef, 0x79, 0xcf, 0x01, 0xdf, 0xf9, 0x9f, 0xe1, 0x8f, 0x39, 0x2f, 0x81 ]
```

Then, I looked at how the flag is encrypted.

```cpp
// Need to decrypt with this
counter = 0;
do {
    cVar1 = FUN_001011e9();
    *(byte *)((long)&local_68 + counter) =
        *(byte *)((long)&local_68 + counter) ^ cVar1 + (char)counter;
    counter = counter + 1;
} while (counter != 0x40);
```

I then re-wrote this function in python to decrypt our flag.

```python
counter = 0 
for byte in encrypted_flag:
    cVar1 = FUN_001011e9()
    decrypted_flag += chr(byte ^ ((cVar1 + counter) & 0xff))
    counter += 1
```

But what about cVar1? What's `FUN_001011e9`? Let's take a look at that and add it to our python script.  

```cpp
void FUN_001011e9(void)

{
  DAT_0010402c = DAT_0010402c * 0x41c64e6d + 0x3039 & 0x7fffffff;
  return;
}
```

Full solve script:

```python
encrypted_flag = [ 0x74, 0x1a, 0x95, 0x4e, 0xba, 0xdb, 0x47, 0x64, 0x09, 0x2d, 0xd1, 0xbf, 0x8a, 0x9d, 0xde, 0x5a, 0xd7, 0x5c, 0x93, 0x16, 0x09, 0x3b, 0x30, 0x6f, 0x97, 0x40, 0xd0, 0x7c, 0x57, 0xdb, 0xde, 0x0c, 0x09, 0xa0, 0x84, 0x9b, 0x8a, 0x76, 0x2f, 0xb1, 0x57, 0xa2, 0xe1, 0x4f, 0xb9, 0x6f, 0x81, 0xbf, 0xb9, 0xbf, 0xe1, 0xef, 0x79, 0xcf, 0x01, 0xdf, 0xf9, 0x9f, 0xe1, 0x8f, 0x39, 0x2f, 0x81, 0xff ]

cVar1 = 0

decrypted_flag = ''

counter = 0 
for byte in encrypted_flag:
    cVar1 = cVar1 * 0x41c64e6d + 0x3039 & 0x7fffffff
    decrypted_flag += chr(byte ^ ((cVar1 + counter) & 0xff))
    counter += 1

print(decrypted_flag)
```

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">MetaCTF{pr0p3r_encrypt10n_1snt_s0_e4sy...}</p>
</details>



___



