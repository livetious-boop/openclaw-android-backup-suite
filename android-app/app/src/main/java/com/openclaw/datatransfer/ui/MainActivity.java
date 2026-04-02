package com.openclaw.datatransfer.ui;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.text.format.Formatter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.openclaw.datatransfer.service.TransferService;

public class MainActivity extends AppCompatActivity {

    private static final int DEFAULT_PORT = 8765;

    private TextView statusText;
    private TextView ipText;
    private EditText passwordInput;
    private EditText portInput;
    private Button startButton;
    private Button stopButton;
    private boolean serviceRunning = false;

    private final ActivityResultLauncher<String[]> permLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), result -> {
                boolean allGranted = result.values().stream().allMatch(v -> v);
                if (allGranted) {
                    startTransferService();
                } else {
                    Toast.makeText(this, "Storage permission required", Toast.LENGTH_LONG).show();
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(getLayoutId());
        initViews();
        displayIpAddress();
    }

    private int getLayoutId() {
        return getResources().getIdentifier("activity_main", "layout", getPackageName());
    }

    private void initViews() {
        statusText = findViewById(getResId("statusText"));
        ipText = findViewById(getResId("ipText"));
        passwordInput = findViewById(getResId("passwordInput"));
        portInput = findViewById(getResId("portInput"));
        startButton = findViewById(getResId("startButton"));
        stopButton = findViewById(getResId("stopButton"));

        portInput.setText(String.valueOf(DEFAULT_PORT));
        stopButton.setEnabled(false);

        startButton.setOnClickListener(v -> checkPermissionsAndStart());
        stopButton.setOnClickListener(v -> stopTransferService());
    }

    private int getResId(String name) {
        return getResources().getIdentifier(name, "id", getPackageName());
    }

    private void displayIpAddress() {
        try {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            String ip = Formatter.formatIpAddress(wm.getConnectionInfo().getIpAddress());
            ipText.setText("Device IP: " + ip);
        } catch (Exception e) {
            ipText.setText("Device IP: Unable to determine");
        }
    }

    private void checkPermissionsAndStart() {
        String pw = passwordInput.getText().toString();
        if (pw.length() < 8) {
            Toast.makeText(this, "Password must be at least 8 characters", Toast.LENGTH_SHORT).show();
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11+ — need MANAGE_EXTERNAL_STORAGE
            if (!android.os.Environment.isExternalStorageManager()) {
                Intent intent = new Intent(android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                startActivity(intent);
                return;
            }
            startTransferService();
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                permLauncher.launch(new String[]{
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                });
            } else {
                startTransferService();
            }
        }
    }

    private void startTransferService() {
        String pw = passwordInput.getText().toString();
        int port;
        try {
            port = Integer.parseInt(portInput.getText().toString());
        } catch (NumberFormatException e) {
            port = DEFAULT_PORT;
        }

        Intent intent = new Intent(this, TransferService.class);
        intent.putExtra("password", pw);
        intent.putExtra("port", port);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }

        serviceRunning = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusText.setText("🟢 Listening for connections on port " + port);
        Toast.makeText(this, "Transfer service started", Toast.LENGTH_SHORT).show();
    }

    private void stopTransferService() {
        stopService(new Intent(this, TransferService.class));
        serviceRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        statusText.setText("🔴 Service stopped");
    }
}
