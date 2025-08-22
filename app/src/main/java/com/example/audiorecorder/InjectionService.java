package com.example.audiorecorder;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import com.topjohnwu.superuser.Shell;

public class InjectionService extends Service {

    private final String TAG = "[INJECTION_SERVICE]";

    static {
        // This allows libsu to report errors and detailed logs
        Shell.enableVerboseLogging = true;
        // Set up the default shell configuration
        Shell.setDefaultBuilder(Shell.Builder.create()
                .setFlags(Shell.FLAG_NON_ROOT_SHELL)
                .setTimeout(10));
    }


    @Override
    public void onCreate() {
        super.onCreate();

    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);
        Log.d(TAG, "Service started...");
        new Thread(() -> {
            Log.d(TAG, "Root shell acquired. Executing command...");

            /////Turning SELinux off
//            Log.d(TAG,"Bypassing SELinux....");
//            String selinuxStatus = executeCommand("getenforce");
//            if(selinuxStatus!="0"){
//                executeCommand("setenforce 0");
//            }

            ////Making the process audioserver able to write into the sdcard directory.

            String bypassCommands = "supolicy --live \"allow audioserver sdcard_type file { create read write open unlink }\"\n" +
                    "supolicy --live \"allow audioserver sdcard_type dir { search read write add_name remove_name }\"\n" +
                    "supolicy --live \"allow audioserver fuse file { create read write open unlink }\"\n" +
                    "supolicy --live \"allow audioserver fuse dir { search read write add_name remove_name }\n"+
                    "supolicy --live \"allow audioserver storage_file file { create read write open unlink }\"\n" +
                    "supolicy --live \"allow audioserver storage_file dir { search read write add_name remove_name }\"\n";
            executeCommand(bypassCommands);
//            Log.d(TAG,"Modifying SELinux rules ->" + result);


            ////Allowing any process to inject into audioserver
            String allowInjectCommand = "supolicy --live \"allow domain audioserver:process { ptrace signal getsched execmem }\"\n" +
                    "supolicy --live \"allow domain audioserver:fd use\"\n" +
                    "supolicy --live \"allow audioserver app_data_file:file { read open execute }\"";
            executeCommand(allowInjectCommand);


            String targetPid = executeCommand("pidof audioserver");
            Log.d(TAG,"Pid of the audioserver process:" + targetPid);
            String localPid = executeCommand("ps -A | grep com.example.audiorecorder | awk '{print $2}'");
            Log.d(TAG,"Pid of the audioRecorder process:" + localPid);

            //Running injector
            String originalInjectorPath = "/sdcard/Download/injector";
            String InjectorPath = "/data/local/tmp/injector";
            executeCommand("mv " + originalInjectorPath + " " + InjectorPath);
            executeCommand("chmod +x " + InjectorPath);
//            String injectionOutput = executeCommand(InjectorPath);

            String originalLibPath = "/sdcard/Download/libhook.so";
            String LibPath = "/data/local/tmp/libhook.so";
            executeCommand("mv " + originalLibPath + " " + LibPath);
            executeCommand("chmod +x " + LibPath);
            String injectionOutput = executeCommand(InjectorPath + " " + targetPid + " " + LibPath + " " + localPid);
//            String injectionOutput = executeCommand("strace -f -o /data/local/tmp/injector.log /data/local/tmp/injector " + targetPid + " " + LibPath);
            Log.d(TAG,injectionOutput);
        }).start();
        return START_NOT_STICKY;
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    public String executeCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            os.writeBytes(command + "\n");
            os.writeBytes("exit\n");
            os.flush();
            os.close();

            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
            process.waitFor();
            return output.toString();
        } catch (Exception e) {
            Log.e(TAG, "Error executing the command: " + command, e);
            return "";
        }
    }

    private String prepareExecutable(String nativeLibDir, String filename) {
        try {
            File libFile = new File(nativeLibDir, filename);
            File outFile = new File("/data/local/tmp", filename);

            // Copy the file from its installed location.
            InputStream in = new FileInputStream(libFile);
            OutputStream out = new FileOutputStream(outFile);
            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
            out.close();

            // Make the file executable using a root command.
            Shell.cmd("chmod 755 " + outFile.getAbsolutePath()).exec();
            return outFile.getAbsolutePath();
        } catch (Exception e) {
            Log.e(TAG, "Error preparing executable " + filename, e);
            return null;
        }
    }
}