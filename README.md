# IAT_Hook_Demo
A demo for dll injection to hook an exe's IAT (import address table) 

In order to try this project- download all of the files and compile the *.c files into exe (Remember - the DllMain should be compiled into dll - I used Visual Studio for it, 
but if you don't know how to do that, you can use the Dll.dll file I have provided.

Put the dll and the injector exe in the same folder. 
You need to run the victim and then the injector. Put the number you see in the victim screen (it's the victim's PID - process id) in the injector terminal. 
The number you see on the victim's screen should change to 1337 - the hooked function's  return value (you can change it in the DllMain.c file and compile again into dll.
the dll name you need to provide to the injector should be Dll.dll but you can change that in the InjectorMain.c file and compile to an exe again). 

**THIS IS ALL FOR EDUCATIONAL CONTENT ONLY**
