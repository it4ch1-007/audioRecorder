## Description of Design
**It is configured for x86_64 architectures Android devices for now.**

1. **POC Application**
- This is the Android application that spawns a service in the background for a short-time interval bypassing the need of a notification to launch a service added to Android (>8.0).
- In the case of an exploit, it can gain the root in the Android device directly and can run the commands directly as root.
- But in my case, I had the magisk rooted Android device and thus I used the `libsu` API of magisk application to execute root commands after elevating my process using magisk.
- The `InjectionService` of this application runs with elevates privileges due to the magisk granted shell. It also runs the injector process in a privileged process that writes and loads the hook library into the remote target process.

<img width="686" height="267" alt="Pasted image 20250823183740" src="https://github.com/user-attachments/assets/2b97eff9-2036-40b3-bd7a-53d545f2733f" />


2. **Injector** (Inside the main **app** directory as injector.cpp)
- The injector binary is designed exclusively for x86_64 architecture Android devices. It injects any shared object native library inside any process using the pid of the target process.
- It uses `ptrace` syscall to stop the target process in its state and modify the registers of the process in order to call the functions inside the injected code, or write the code inside the target process' memory.
- Then at last it restores the last state of the process again and continues the process.
- Its main objective is just to write the library's code into the memory of the target process using `ptrace` and call that hook library using `dlopen` method.

3. **Hooking library**
- This library hooks the functions of the `audioserver` process in the Android device and tries to achieve various goals like:
	- Trigger the main hooks when VoIP mode is in `MODE_IN_COMMUNICATION`, and monitor the mode in real-time by hooking the function `AudioFlinger::setMode()`.
	- It captures the audio packets in the format of PCM by hooking the `AudioStreamOut::write()`.
- It uses the custom Native inline hooking mechanism that hooks the functions of an elf inside Android device using various symbol resolution methods and the address resolving techniques.
	- The basic principle of the method used here is to jump the RIP register to our code written into the target process' memory and then get it back to ensure the process does'nt crash.
	- The arguments are supplied to the function using the `RDI,RSI,RCX,RDX` and the result of the function called is obtained through `RAX` register to ensure that the hooks are applied inside the remote library.
- Both address offset resolving and symbol lookup resolving methods were added in the hook file to be able to get the desired values and buffers.

4. **SElinux Bypass**
- This can be first easily bypassed using the command `setenforce 0` with root privileges.
- There was a general method that can be used to accomplish this that was to use a custom magisk module to be able to modify the booting and init process of the Android device.The magisk app would modify and add custom SELinux rules in the policy of the Android device during the init process. But this was only limited to the devices rooted with Magisk patched ROM.
- The second method is to modify the files governing the selinux inside the Android OS. 
	- If there is `selinuxfs` inside the `/proc/filesystems` file then selinux is enabled.
	- To disable selinux, we can just write `mountPath/enforce` file with 0s that will disable selinux.
	<img width="1206" height="575" alt="Pasted image 20250823182502" src="https://github.com/user-attachments/assets/e5120e34-ecb9-4c13-81b7-d935b05884f6" />

- The method I used in this project is to add custom rules using `supolicy` inside the Android device. This was used to allow the audioserver process to write into the external storage directory (sdcard) and also allow our process to inject code into its process' memory making our process more hidden.
---

## Writing the output (Maintaining real-time PCM data packets)
- Both the hooked functions `newAudioStreamOutWrite` and `newAudioStreamInRead` have their own buffers that contain the small chunks of pcm data coming from into the `libaudioflinger.so`.
- To maintain authenticity and info about each chunk. Each chunk is transferred into the format {timestamp,AudioDirection,AudioType,dataBytes} using the structure Packet.
- Even if the user doesn't speak the PCM data is transferred with the `ampluitude = 0`. This will corrupt our data and fill the pcm bytes with the silenced sound. To tackle this, I have used `VAD` (Voice Activity Dectector) check that tells if the chunk of data resembled silenced data or not using Fast Fourier Transform algorithm to determine its amplitude.
- The hangover delay is introduced in order to maintain the situations where the silenced voice follows the person's authentic voice to not get only non-silenced voices and maintain pauses between the speeches.
- Using the conversion state structure, I have implemented silencing the packets and writing it to the output file only when both the streams are silenced.
- A custom thread-safe priority queue is used to store the packets incoming from both the streams that easily provide us the packet with the earliest timestamp in real-time. This bypasses the need to sort them again and again after storing in any order. And also it satisfies the need to handle the case when two packets have the same timestamps (is very rare as timestamps are used in nano seconds).
- The queue is made and used as a bounded queue to make sure that it doesn't deny any data from either of the streams.
- A separate thread `The writer thread` is used to write to the file in real-time using the earliest possible timestamp inside the `audio_queue`.

```
If specified or desired then we can also write the direction of the stream alongwith its pcm data bytes. This will allow us to differentiate it if we are reading it using a python script. But the audio difference can be easily identified even if the data bytes are directly written into the output file.
```


## Testing

The project was successfully tested on Android 14 x86_64 emulator of Pixel 6 in Android Studio AVD format.
(However it sometimes encounter some issues while running on the archs that issue still needs to be resolved. Maybe it is due to the fact that I am using the direct dumping method on a circular buffer that is resulting in errors.)
---
## Process to identify the target functions
- First thing is to get the value of mode inside the library constantly to know if any VoIP call is being made in real-time.
	- This is done by hooking the `AudioFlinger::setMode()` function inside the libaudioflinger.so library.
	- We will use the symbol associated with the function `_ZN7android12AudioFlinger7setModeEi` to hook the function.
	- The mode value is passed as an argument to this function and so we can capture it simply by hooking the function and obtaining its arguments.
<img width="1958" height="967" alt="Pasted image 20250823182914" src="https://github.com/user-attachments/assets/0c2b66a8-247a-432e-ad66-753c82d1f4c5" />

- Second thing is to get the value of PCM packets from the buffers inside the Threads.cpp
	- This is done by hooking the `PlaybackThread::threadLoop_write()` function inside `Threads.cpp` inside the AOSP code and can be found inside the `libaudioflinger.so` library using the `mOutput->write()` method hooking. This method contains the buffer having the PCM packets data as its first argument so this can be used to dump their data.
    - The native library obtained from the Android device was stripped and so it had to be loaded with Android native symbols to be able to identify stripped symbols too using IDA Pro symbol loading feature.
	- This was done after dynamic debugging of the `libaudioflinger.so` library and the obtained results showed that the PCM packets were being passed to this hooked function and this was used to write the buffer to the HAL `Hardware Abstraction Layer`. Before this could happen we dumped the PCM packets inside the external storage directory. 
	<img width="1646" height="1048" alt="Pasted image 20250823182426" src="https://github.com/user-attachments/assets/5a8c769c-8d2b-415a-b3ff-9f9a642d861b" />

	<img width="1958" height="967" alt="Pasted image 20250823183056" src="https://github.com/user-attachments/assets/39f77c21-8820-4a74-bb7f-69341a40faf3" />

<img width="1958" height="967" alt="Pasted image 20250823183523" src="https://github.com/user-attachments/assets/e9f7af6c-fdac-4937-ba26-1af841076f61" />

---

## Running the POC code

- There are two files `Injector.cpp` and `hook.cpp` that have to be compiled using the bash script `compile.sh`. The Android ndk toolchains path and the adb must be in the path of the shell for this to work.
<img width="363" height="788" alt="Pasted image 20250823182659" src="https://github.com/user-attachments/assets/9dd997b3-a0ad-4818-a729-15418e76d7af" />

- This script basically compiles the `injector` and `libhook.so` outside the Android studio giving us more control over the binaries and their paths inside the Android device.
	- Build the audioRecorder app and start the `InjectionService` using the `Start Service` button on the MainActivity of the app. 
- Make a call to test the working of the poc code and obtain the file named `capturedPcm.dat` that will have all the data of the PCM packets.
---

## Challenges encountered

- The first challenge was to execute commands silently. This was accomplished using the libSu api of Magisk but it was unable to recognise my Application as an app that is demanding root and was not showing it on the UI. So I spent a lot of time debugging and trying to identify the root problem. But ultimately I found out that the UI just passes the application's internal database `magisk.db` . Thus I pulled out the database itself and modified it using `sqlite3` and gained root silently for every command I execute using the application.
<img width="355" height="721" alt="Pasted image 20250823182808" src="https://github.com/user-attachments/assets/8b37e24c-8d13-49e8-b576-60ede8bd8972" />

- The second challenge was configuring Android studio to use Dobby or some other frameworks for hooking. I guess it would be much easier to use these already made frameworks for hooking but I wanted to experiment more with my custom inline hooking framework I wrote during my previous project on zygisk detection , so I went through with my inline hook and modified it best to my use.
<img width="1372" height="1166" alt="Pasted image 20250823182738" src="https://github.com/user-attachments/assets/50972847-e82f-40d4-83f5-24c3140ed51b" />


- The main challenge I faced in this was identifying the function to capture the buffers that will contain the pcm packets. To find some functions regarding this, I reverse engineered the AOSP code files responsible for the handling of PCM packets buffers  inside the `libaudioflinger.so`  library. This gave me a basic idea of which functions are actually responsible for the buffer handling. Then to get an advanced idea of how these buffers are handled step by step, I debugged the `libaudioflinger.so` library using dynamic Android debugger of IDA Pro. I identified some general functions like `memcpy,read and others` were used inside the `Threads.cpp` program code and they can be hooked to get the control of those buffers. So ultimately I hooked the `AudioStreamOut::write()` method in order to get the buffer as it is passed to it as argument and then dump it to the external storage directory.

- There is a scope of error if the FFT algorithm used here to determine if the pcm packet is silenced or not, takes a long time to determine the amplitude of the data. If this happens, then it may lead to loss of data. The solution might be to use a better and simpler as well as faster algorithm than FFT.
---

## External resources used
- https://github.com/topjohnwu/libsu
- https://cs.android.com/
- https://forum.tuts4you.com/topic/38546-function-hooking-on-x64/
- https://dev.to/wireless90/inline-function-hooking-android-internals-ctf-ex5-pjh
- https://github.com/strazzere/inject-hooks-android-rs
- https://github.com/AlbertoFormaggio1/Voice-Activity-Detector
