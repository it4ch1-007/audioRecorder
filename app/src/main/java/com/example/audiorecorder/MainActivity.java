package com.example.audiorecorder;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.example.audiorecorder.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button startAttackBtn = findViewById(R.id.startAttackBtn);
        startAttackBtn.setOnClickListener(v->{
            attackFn();
        });
        Button stopAttackBtn = findViewById(R.id.stopAttackBtn);
        stopAttackBtn.setOnClickListener(v->{
            Intent stopIntent = new Intent(this,InjectionService.class);
            stopService(stopIntent);
            Toast.makeText(this,"Injection Service Stopped..",Toast.LENGTH_SHORT).show();
        });

    }

    public void attackFn(){
        Intent attackIntent = new Intent(this,InjectionService.class);
        startService(attackIntent);
        Toast.makeText(this,"Injection Service Started..",Toast.LENGTH_SHORT).show();
    }
}