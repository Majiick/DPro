# DPro
A not-very-good 32-bit executable protector. Good learning though.

To protect an executable, so I don't forget myself because I didn't automate this:
	1. Change FileDirectory fileDirectoryInfo; in Source.cpp main() to point to the right input file and output folders.
	2. Change the FILE_SIZE constant in Source.cpp to the file size of the executable.
	(Optional: Change the encryption key.)
	3. Compile and run Source.cpp
	4. Change the include file names in stubGen.asm to the files outputted by Source.cpp.
	5. Compile and run stubGen.asm.
	6. Voila. But if you want to retain the .rsrc section for the icon, then look at where the .rsrc section is and change the .rsrc directory to point to it. You can do this using CFF explorer.