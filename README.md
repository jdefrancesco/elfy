Author: Joey DeFrancesco
Shouts: dlab

Summary: a project I did in high school (circa 2006) with 
my friend devon who passed away.  RIP. 

elf: 
  Overwrites .note with some shellcode and changes entry point to 
  shellcode

elf2: 
  Overwrites .comment with some shellcode, finds closest LOAD entry to
  .comment, extends LOAD entry to include .comment, marks LOAD entry 
  executable, and changes entry point to shellcode

Latter is more complex, but you can often use much larger shellcode

Errata:
stripping a binary (strip -s) will break things.
marking segment executable might cause problems on W^X boxes,
might have to create new LOAD entry specifically for us..

these will be looked into /eventually/..

