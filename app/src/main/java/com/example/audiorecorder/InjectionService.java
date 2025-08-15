package com.example.audiorecorder;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;

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
            String targetPid = executeCommand("pidof audioserver");
            Log.d(TAG,"Pid of the audioserver process:" + targetPid);
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
}