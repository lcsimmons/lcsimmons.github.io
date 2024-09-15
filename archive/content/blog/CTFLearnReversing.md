+++
title = "CTFLearn Reversing"
date = 2022-02-19
description = "Here's some writeups from the reversing category on ctflearn.com/"
+++

### Table of Contents:

<div class="toc">

- [PIN (Medium)](#pin-medium)
- [REverseDIS (Medium)](#reversedis-medium)
- [PyDis (Medium)](#pydis-medium)

</div>

<center>

## PIN (Medium)

</center>

We are given `rev1` and our goal is to uncover the PIN. I loaded the binary into Ghidra and navigated to the main function. 

```c
undefined8 main(void)

{
  int iVar1;
  undefined4 local_c;
  
  printf("Masukan PIN = ");
  __isoc99_scanf(&DAT_004006d3,&local_c);
  iVar1 = cek(local_c);
  if (iVar1 == 0) {
    puts("PIN salah ! \n");
  }
  else {
    puts("PIN benar ! \n");
  }
  return 0;
}
```

After glancing through this, I figured that local_c is what we input for the pin, and we want `cek(local_c)` to return 1, so I decided to look at `cek()`

```c
bool cek(int param_1)

{
  return param_1 == valid;
}
```

This compares our input to `valid`, so we want our input to match `valid`'s value

```
valid                                           XREF[2]:     Entry Point(*), cek:004005bd(R)  
00601040 15 16 05 00     undefined4 00051615h
```

I converted `valid`'s hex value of `00051615` into decimal, giving us our PIN `333333`

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">CTFLearn{333333}</p>
</details>

___

<center>

## REverseDIS (Medium)

</center>

Ghidra time. 

```c
undefined8 main(void)

{
  int local_10;
  int local_c;
  
  printf("Input password: ");
  __isoc99_scanf(&DAT_001008f5,input);
  for (local_10 = 0; local_10 < 0x16; local_10 = local_10 + 1) {
    *(int *)(key2 + (long)local_10 * 4) = (int)key[local_10];
    msg[local_10] =
         (byte)*(undefined4 *)(key2 + (long)local_10 * 4) ^
         (byte)*(undefined4 *)(str + (long)local_10 * 4);
  }
  for (local_c = 0; local_c < 0x16; local_c = local_c + 1) {
    if (input[local_c] != msg[local_c]) {
      stat = 0;
    }
  }
  if (stat == 0) {
    puts("Wrong password");
  }
  else {
    puts("Good job dude !!!");
  }
  return 0;
}
```

At first, I thought that I would have to reverse the encryption, but as I was poking around, I found a lot of undefineds and figured that I probably didn't want to approach this statically.

I did, however, note that the second for loop in `main` just checks to see if `input` == `msg` so I wanted to see if I could grab the value of `msg` at the end of main in gdb. 

```
gef➤  x/s 0x555555601140
0x555555601140 <msg>:   "AbCTF{r3vers1ng_dud3}"
```

___

<center>

## PyDis (Medium)

</center>

We are given `dis.txt` with python bytecode and the output `éÿîÅËÎÞÃÙóÙÕÎÈÊúèÞÎÜÌÌÕÓÕìùÂéçÆÐþÿñÖËîÿôÿ`.


Using https://docs.python.org/3/library/dis.html for reference, I translated the bytecode back into python.

```python
def func2(c1,c2):
    tmp1 = c2
    tmp2 = c1
    return tmp1 ^ tmp2

def func():
    fp = open('flag.txt').read()
    cipher = ''
    for i in range(len(fp)): #range(70?) #FOR_ITER(delta)
        temp = func2(ord(fp[i]), 170) #BINARY_SUBSCR TOS1[TOS]
        cipher = cipher + chr(func2(temp,i))
    print(cipher)
    f = open('encrypted_flag.txt', 'w')
    f.write(cipher)
```

I then used this to decrypt the given output.

```python 
output = "éÿîÅËÎÞÃÙóÙÕÎÈÊúèÞÎÜÌÌÕÓÕìùÂéçÆÐþÿñÖËîÿôÿ"
decrypted = ''

for i in range(len(output)):
    temp = func2(ord(output[i]), 170)
    decrypted += chr(func2(temp,i))
print(decrypted)
```

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">CTFlearn{Python_Reversing_Is_Pretty_Easy}</p>
</details>

