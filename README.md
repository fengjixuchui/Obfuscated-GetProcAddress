# Obfuscated GetProcAddress
Ok this isn't really get ProcAddress.
The goal of this project is to circumvent GetProcAddress and the storage of raw function names by using a different method.
It iterates through the function names of the specified API and compares their hash with the hardcoded one. If it matches, it is the function we are looking for.
