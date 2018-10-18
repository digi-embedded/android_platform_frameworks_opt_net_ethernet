/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright (C) 2018 Digi International Inc.
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
import android.net.EthernetManager;
import android.net.IEthernetManager;
import android.net.IEthernetServiceListener;
import android.net.IpConfiguration;
import android.net.IpConfiguration.IpAssignment;
import android.net.IpConfiguration.ProxySettings;
import android.net.NetworkInfo;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.INetworkManagementService;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.provider.Settings;
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
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * EthernetServiceImpl handles remote Ethernet operation requests by implementing
 * the IEthernetManager interface.
 *
 * @hide
 */
public class EthernetServiceImpl extends IEthernetManager.Stub {

    // Constants
    private static final String TAG = "EthernetServiceImpl";

    private static final String HW_ADDRESS_PATH = "/sys/class/net";
    private static final String HW_ADDRESS_FILE = "address";

    private static final String ERROR_CONTEXT_NULL = "Context cannot be null";
    private static final String ERROR_INFO_NULL = "Ethernet info cannot be null";

    // Variables.
    private String iface;

    private ConnectivityManager connManager;

    private final Context mContext;
    private final EthernetConfigStore mEthernetConfigStore;
    private final AtomicBoolean mStarted = new AtomicBoolean(false);
    private IpConfiguration mIpConfiguration;

    private Handler mHandler;
    private final EthernetNetworkFactory mTracker;
    private final RemoteCallbackList<IEthernetServiceListener> mListeners =
            new RemoteCallbackList<IEthernetServiceListener>();

    private INetworkManagementService nmService;

    public EthernetServiceImpl(Context context) {
        if (context == null)
            throw new NullPointerException(ERROR_CONTEXT_NULL);

        mContext = context;

        Log.i(TAG, "Creating EthernetConfigStore");
        mEthernetConfigStore = new EthernetConfigStore();
        mIpConfiguration = mEthernetConfigStore.readIpAndProxyConfigurations();

        Log.i(TAG, "Read stored IP configuration: " + mIpConfiguration);

        mTracker = new EthernetNetworkFactory(mListeners);
    }

    private void enforceAccessPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_NETWORK_STATE,
                "EthernetService");
    }

    private void enforceChangePermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CHANGE_NETWORK_STATE,
                "EthernetService");
    }

    public void start() {
        Log.i(TAG, "Starting Ethernet service");

        HandlerThread handlerThread = new HandlerThread("EthernetServiceThread");
        handlerThread.start();
        mHandler = new Handler(handlerThread.getLooper());

        mTracker.start(mContext, mHandler);

        connManager = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);

        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        nmService = INetworkManagementService.Stub.asInterface(b);

        // Get the Ethernet interface.
        String[] ifList = listInterfaces();
        if (ifList != null && ifList.length > 0)
                iface = ifList[0];

        // If the Ethernet property does not exist, create it. Ethernet is always enabled on first boot.
        String prop = SystemProperties.get(String.format(EthernetProperties.ETH_PROPERTY, iface));
        if (prop == null || prop.isEmpty())
                SystemProperties.set(String.format(EthernetProperties.ETH_PROPERTY, iface), 
                        EthernetProperties.ETH_PROPERTY_ENABLED);

        mStarted.set(true);
    }

    /**
     * Returns the Ethernet interface name.
     *
     * @return The Ethernet interface name, {@code null} if there is not any
     *         interface.
     */
    @Override
    public String getInterfaceName() {
        enforceAccessPermission();

        return iface;
    }

    /**
     * Returns whether the Ethernet interface is connected or not.
     *
     * @return {@code true} if connected, {@code false} otherwise.
     */
    @Override
    public boolean isConnected() {
        enforceAccessPermission();

        NetworkInfo info = connManager.getNetworkInfo(ConnectivityManager.TYPE_ETHERNET);
        if (info != null)
            return info.isConnected();
        return false;
    }

    /**
     * Resets the Ethernet interface.
     */
    @Override
    public void resetInterface() {
        enforceChangePermission();

        if (iface == null || !isEnabled(iface))
            return;

        synchronized (this) {
            Log.d(TAG, "Reset device " + iface);
            mTracker.stop();
            mTracker.start(mContext, mHandler);
        }
    }

    /**
     * Reads the MAC address of the Ethernet interface.
     *
     * @return The MAC address or {@code null} if could not be read.
     *
     * @throws NullPointerException If the configured interface is null.
     */
    @Override
    public String getMacAddress() {
        enforceAccessPermission();

        if (iface == null)
            throw new NullPointerException("Null interface name");

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(new File(HW_ADDRESS_PATH +
                    File.separator + iface, HW_ADDRESS_FILE)));
            String value = reader.readLine();
            if (value != null)
                return value.trim();
        } catch (IOException e) {
            Log.e(TAG, "Could not read MAC address: " + e);
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
    public IpConfiguration getConfiguration() {
        enforceAccessPermission();

        synchronized (mIpConfiguration) {
            return new IpConfiguration(mIpConfiguration);
        }
    }

    /**
     * Set Ethernet configuration
     */
    @Override
    public void setConfiguration(IpConfiguration config) {
        if (!mStarted.get()) {
            Log.w(TAG, "System isn't ready enough to change ethernet configuration");
        }

        enforceChangePermission();

        long token = Binder.clearCallingIdentity();
        synchronized (mIpConfiguration) {
            mEthernetConfigStore.writeIpAndProxyConfigurations(config);

            // TODO: this does not check proxy settings, gateways, etc.
            // Fix this by making IpConfiguration a complete representation of static configuration.
            if (!config.equals(mIpConfiguration)) {
                mIpConfiguration = new IpConfiguration(config);
                mTracker.stop();
                mTracker.start(mContext, mHandler);
            }
        }
        Binder.restoreCallingIdentity(token);
    }

    /**
     * Indicates whether the system currently has one or more
     * Ethernet interfaces.
     */
    @Override
    public boolean isAvailable() {
        enforceAccessPermission();
        return mTracker.isTrackingInterface();
    }

    /**
     * Addes a listener.
     * @param listener A {@link IEthernetServiceListener} to add.
     */
    public void addListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mListeners.register(listener);
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
        mListeners.unregister(listener);
    }

    /**
     * Returns a list with the Ethernet interfaces.
     *
     * @return A list with the Ethernet interfaces.
     */
    @Override
    public String[] listInterfaces() {
        enforceAccessPermission();
        String sIfaceMatch = mContext.getResources().getString(
                com.android.internal.R.string.config_ethernet_iface_regex);
        ArrayList<String> ifaces = new ArrayList<>();
        long token = Binder.clearCallingIdentity();
        try {
            // Get the Ethernet interfaces.
            for (String iface : nmService.listInterfaces()) {
                if (iface.matches(sIfaceMatch))
                    ifaces.add(iface);
            }
        } catch (RemoteException e) {
            Log.e(TAG, "Could not get list of interfaces " + e);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
        return ifaces.toArray(new String[0]);
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
            if (enable)
                nmService.setInterfaceUp(iface);
            else
                nmService.setInterfaceDown(iface);
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
     * Returns whether the interface is enabled or not.
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
            NetworkInterface nIface = NetworkInterface.getByName(iface);
            if (nIface != null)
                return nIface.isUp();
        } catch (SocketException e) {
            Log.e(TAG, "Could not retrieve interface status: " + e);
        }
        return false;
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

        pw.println();
        pw.println("Stored Ethernet configuration: ");
        pw.increaseIndent();
        pw.println(mIpConfiguration);
        pw.decreaseIndent();

        pw.println("Handler:");
        pw.increaseIndent();
        mHandler.dump(new PrintWriterPrinter(pw), "EthernetServiceImpl");
        pw.decreaseIndent();
    }
}
