package com.recover.agent;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class MainActivity extends Activity {
    private static final String TAG = "RecoverAgent";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "Agent started, dumping data...");
        try {
            File outDir = getExternalFilesDir(null);
            if (outDir != null) {
                dumpSms(outDir);
                dumpContacts(outDir);
                dumpCallLogs(outDir);
            }
            Log.d(TAG, "Data dump completed successfully.");
        } catch (Exception e) {
            Log.e(TAG, "Error dumping data", e);
        }
        finish();
    }

    private void dumpSms(File dir) {
        File file = new File(dir, "sms_dump.json");
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            ContentResolver cr = getContentResolver();
            Cursor cursor = cr.query(Uri.parse("content://sms/"), null, null, null, null);
            out.print("[");
            if (cursor != null) {
                int count = 0;
                while (cursor.moveToNext()) {
                    if (count > 0) out.print(",");
                    out.print("{");
                    boolean firstField = true;
                    for (int i = 0; i < cursor.getColumnCount(); i++) {
                        String name = cursor.getColumnName(i);
                        String val = cursor.getString(i);
                        if (val != null) {
                            if (!firstField) out.print(",");
                            out.print(jsonEscape(name) + ":" + jsonEscape(val));
                            firstField = false;
                        }
                    }
                    out.print("}");
                    count++;
                }
                cursor.close();
            }
            out.print("]");
        } catch (Exception e) {
            Log.e(TAG, "Sms dump failed", e);
        }
    }

    private void dumpContacts(File dir) {
        File file = new File(dir, "contacts_dump.json");
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            ContentResolver cr = getContentResolver();
            Cursor cursor = cr.query(Uri.parse("content://contacts/phones/"), null, null, null, null);
            out.print("[");
            if (cursor != null) {
                int count = 0;
                while (cursor.moveToNext()) {
                    if (count > 0) out.print(",");
                    out.print("{");
                    boolean firstField = true;
                    for (int i = 0; i < cursor.getColumnCount(); i++) {
                        String name = cursor.getColumnName(i);
                        String val = cursor.getString(i);
                        if (val != null) {
                            if (!firstField) out.print(",");
                            out.print(jsonEscape(name) + ":" + jsonEscape(val));
                            firstField = false;
                        }
                    }
                    out.print("}");
                    count++;
                }
                cursor.close();
            }
            out.print("]");
        } catch (Exception e) {
            Log.e(TAG, "Contacts dump failed", e);
        }
    }

    private void dumpCallLogs(File dir) {
        File file = new File(dir, "calllogs_dump.json");
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            ContentResolver cr = getContentResolver();
            Cursor cursor = cr.query(Uri.parse("content://call_log/calls/"), null, null, null, null);
            out.print("[");
            if (cursor != null) {
                int count = 0;
                while (cursor.moveToNext()) {
                    if (count > 0) out.print(",");
                    out.print("{");
                    boolean firstField = true;
                    for (int i = 0; i < cursor.getColumnCount(); i++) {
                        String name = cursor.getColumnName(i);
                        String val = cursor.getString(i);
                        if (val != null) {
                            if (!firstField) out.print(",");
                            out.print(jsonEscape(name) + ":" + jsonEscape(val));
                            firstField = false;
                        }
                    }
                    out.print("}");
                    count++;
                }
                cursor.close();
            }
            out.print("]");
        } catch (Exception e) {
            Log.e(TAG, "CallLogs dump failed", e);
        }
    }

    private String jsonEscape(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append("\"");
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < ' ') {
                        String t = "000" + Integer.toHexString(ch);
                        sb.append("\\u" + t.substring(t.length() - 4));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
