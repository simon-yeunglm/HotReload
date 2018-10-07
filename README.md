# HotReload
A sample project of hot-reload DLL on Windows.  
More info can be found on my [blog](http://simonstechblog.blogspot.com/2018/10/testing-hot-reload-dll-on-windows.html).  

<img src=https://3.bp.blogspot.com/-3HEXCXmcx18/W7nNnTFmj-I/AAAAAAAABKA/w8RXQPvveTY10HaQ0hCndEewAJuZqE5IQCLcBGAs/s640/hot_reload.gif width=640 />

### How it works
When the program loads a DLL:  
```
1. copy its associated PDB file.  
2. copy the target DLL file and modify the hard coded PDB path to newly copied PDB path done in step 1.  
3. load the copied DLL in step 2 instead.  
```
After editing some code:
```
4. detach the debugger to compile the DLL from Visual Studio.  
5. unload the copied DLL.  
6. repeat the above step 1 to 3.  
7. re-attach the debugger.  
```

### Running the sample program
```
1. in Visual Studio, press F5 to compile and run the program with debugger.  
2. edit some code, then press F7 to re-build the solution.  
3. press enter to confirm the "Do you want to stop debugging?" dialog.  
4. the program will reload the new DLL and re-attach the debugger automatically after compilation.  
```
