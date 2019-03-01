/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright (C) 2018-2019 Digi International Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.ethernet;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.EthernetProperties;
import android.net.IEthernetManager;
import android.net.IEthernetServiceListener;
import android.net.IpConfiguration;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.INetworkManagementService;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.util.Log;
import android.util.PrintWriterPrinter;

import com.android.internal.util.IndentingPrintWriter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * EthernetServiceImpl handles remote Ethernet operation requests by implementing
 * the IEthernetManager interface.
 */
public class EthernetServiceImpl extends IEthernetManager.Stub {

    // Constants.
    private static final String TAG = "EthernetServiceImpl";

    private static final String HW_ADDRESS_PATH = "/sys/class/net";
    private static final String HW_ADDRESS_FILE = "address";

    // Variables.
    private final Context mContext;
    private final AtomicBoolean mStarted = new AtomicBoolean(false);

    private Handler mHandler;
    private EthernetTracker mTracker;

    private final INetworkManagementService nmService;

    private ConnectivityManager connManager;

    public EthernetServiceImpl(Context context) {
        mContext = context;

        nmService = INetworkManagementService.Stub.asInterface(ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE));
        connManager = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    private void enforceAccessPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_NETWORK_STATE,
                "EthernetService");
    }

    private void enforceChangePermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CHANGE_NETWORK_STATE,
                "ConnectivityService");
    }

    public void start() {
        Log.i(TAG, "Starting Ethernet service");

        HandlerThread handlerThread = new HandlerThread("EthernetServiceThread");
        handlerThread.start();
        mHandler = new Handler(handlerThread.getLooper());

        mTracker = new EthernetTracker(mContext, mHandler);
        mTracker.start();

        mStarted.set(true);
    }

    @Override
    public String[] getAvailableInterfaces() throws RemoteException {
        return mTracker.getInterfaces(true);
    }

    /**
     * Returns whether the given Ethernet interface is connected or not.
     *
     * @param iface Ethernet interface.
     *
     * @return {@code true} if connected, {@code false} otherwise.
     */
    @Override
    public boolean isConnected(String iface) {
        if (iface == null)
            return false;

        enforceAccessPermission();
        Log.d(TAG, "Get connectivity of interface " + iface);
        String macAddr = getMacAddress(iface);
        if (connManager == null)
            connManager = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        for (Network network:connManager.getAllNetworks()) {
            NetworkInfo networkInfo = connManager.getNetworkInfo(network);
            if (networkInfo.getType() != ConnectivityManager.TYPE_ETHERNET)
                continue;
            if (!networkInfo.getExtraInfo().equalsIgnoreCase(macAddr))
                continue;
            return networkInfo.isConnected();
        }
        return false;
    }

    /**
     * Returns whether the given interface is enabled or not.
     *
     * @param iface Ethernet interface.
     *
     * @return {@code true} if the interface is enabled, {@code false}
     *         otherwise.
     */
    @Override
    public boolean isEnabled(String iface) {
        if (iface == null)
            return false;

        enforceAccessPermission();
        try {
            Log.d(TAG, "Get state of interface " + iface);
            NetworkInterface nIface = NetworkInterface.getByName(iface);
            if (nIface != null)
                return nIface.isUp();
        } catch (SocketException e) {
            Log.e(TAG, "Could not retrieve interface status: " + e);
        }
        return false;
    }

    /**
     * Enables or disables the given interface.
     *
     * @param iface Ethernet interface.
     * @param enable {@code true} to enable it, {@code false} to disable it.
     */
    @Override
    public void setEnabled(String iface, boolean enable) {
        if (iface == null)
            return;

        enforceChangePermission();
        long token = Binder.clearCallingIdentity();
        try {
            synchronized (this) {
                if (enable) {
                    Log.d(TAG, "Enable interface " + iface);
                    nmService.setInterfaceUp(iface);
                } else {
                    Log.d(TAG, "Disable interface " + iface);
                    mTracker.updateInterfaceState(iface, false);
                    nmService.clearInterfaceAddresses(iface);
                    nmService.setInterfaceDown(iface);
                }
            }
        } catch (RemoteException e) {
            Log.e(TAG, "Could not change the state of the interface " + e);
        } finally {
            Binder.restoreCallingIdentity(token);
            // Update the Ethernet enabled system property.
            SystemProperties.set(String.format(EthernetProperties.ETH_PROPERTY, iface),
                    enable ? EthernetProperties.ETH_PROPERTY_ENABLED : EthernetProperties.ETH_PROPERTY_DISABLED);
        }
    }

    /**
     * Resets the given Ethernet interface.
     *
     * @param iface Ethernet interface.
     */
    @Override
    public void resetInterface(String iface) {
        if (iface == null)
            return;

        enforceChangePermission();
        long token = Binder.clearCallingIdentity();
        try {
            synchronized (this) {
                Log.d(TAG, "Reset interface " + iface);
                nmService.setInterfaceDown(iface);
                nmService.setInterfaceUp(iface);
            }
        } catch (RemoteException e) {
            Log.e(TAG, "Could not reset the interface " + e);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    /**
     * Reads the MAC address of the given Ethernet interface.
     *
     * @param iface Ethernet interface.
     *
     * @return The MAC address or {@code null} if could not be read.
     */
    @Override
    public String getMacAddress(String iface) {
        if (iface == null)
            return null;

        enforceAccessPermission();
        BufferedReader reader = null;
        try {
            Log.d(TAG, "Read MAC address of interface " + iface);
            reader = new BufferedReader(new FileReader(new File(HW_ADDRESS_PATH +
                    File.separator + iface, HW_ADDRESS_FILE)));
            String value = reader.readLine();
            if (value != null)
                return value.trim();
        } catch (IOException e) {
            Log.e(TAG, "Could not read MAC address of interface '" + iface + "': " + e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {}
            }
        }

        return null;
    }

    /**
     * Get Ethernet configuration
     * @return the Ethernet Configuration, contained in {@link IpConfiguration}.
     */
    @Override
    public IpConfiguration getConfiguration(String iface) {
        enforceAccessPermission();

        Log.d(TAG, "Get configuration of interface " + iface);

        return new IpConfiguration(mTracker.getIpConfiguration(iface));
    }

    /**
     * Set Ethernet configuration
     */
    @Override
    public void setConfiguration(String iface, IpConfiguration config) {
        if (!mStarted.get()) {
            Log.w(TAG, "System isn't ready enough to change ethernet configuration");
        }

        enforceChangePermission();

        Log.d(TAG, "Set configuration of interface " + iface + ": " + config);

        // TODO: this does not check proxy settings, gateways, etc.
        // Fix this by making IpConfiguration a complete representation of static configuration.
        mTracker.updateIpConfiguration(iface, new IpConfiguration(config));
    }

    /**
     * Indicates whether given interface is available.
     */
    @Override
    public boolean isAvailable(String iface) {
        enforceAccessPermission();

        Log.d(TAG, "Check availability of interface " + iface);

        return mTracker.isTrackingInterface(iface);
    }

    /**
     * Adds a listener.
     * @param listener A {@link IEthernetServiceListener} to add.
     */
    public void addListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mTracker.addListener(listener, true);
    }

    /**
     * Removes a listener.
     * @param listener A {@link IEthernetServiceListener} to remove.
     */
    public void removeListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mTracker.removeListener(listener);
    }

    @Override
    protected void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        final IndentingPrintWriter pw = new IndentingPrintWriter(writer, "  ");
        if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                != PackageManager.PERMISSION_GRANTED) {
            pw.println("Permission Denial: can't dump EthernetService from pid="
                    + Binder.getCallingPid()
                    + ", uid=" + Binder.getCallingUid());
            return;
        }

        pw.println("Current Ethernet state: ");
        pw.increaseIndent();
        mTracker.dump(fd, pw, args);
        pw.decreaseIndent();

        pw.println("Handler:");
        pw.increaseIndent();
        mHandler.dump(new PrintWriterPrinter(pw), "EthernetServiceImpl");
        pw.decreaseIndent();
    }
}
