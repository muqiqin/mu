package com.android.settings;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkConfigInfo;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.SystemProperties;
import android.preference.ValuePreference;
import android.text.TextUtils;

import com.android.settings.item.NvramUtil;

import android.net.ethernet.EthernetManager;

/**
 * Created by hjiang on 17-4-18.
 */
public class NetStatusInfoSettings extends SettingsPreferenceFragment {

    private static final String KEY_MACADDRESS = "mac_address";
    private static final String KEY_ADDRESSTYPE = "address_type";
    private static final String KEY_IPADDRESS = "ip_address";
    private static final String KEY_SUBNETMASK = "subnet_mask";
    private static final String KEY_DEFAULTGATEWAY = "default_gateway";
    private static final String KEY_DNSSERVER = "dns_server";
    private static final String KEY_ADNSSERVER = "a_dns_server";
    private static final String KEY_NATTYPE = "nat_type";
    private static final String KEY_VPNIP = "vpn_ip";

    private static final String KEY_IPV6_ADDRESS = "ipv6_address";
    private static final String KEY_IPV6_DNS1 = "ipv6_dns1";
    private static final String KEY_IPV6_DNS2 = "ipv6_dns2";


    private ValuePreference mMACAddress;
    private ValuePreference mAddressType;
    private ValuePreference mIPAddress;
    private ValuePreference mSubnetMask;
    private ValuePreference mDefalutGateway;
    private ValuePreference mDNSServer;
    private ValuePreference mADNSServer;
    private ValuePreference mNATType;
    private ValuePreference mVPNIP;

    private ValuePreference mIPv6Adress;
    private ValuePreference mIPv6Dns1;
    private ValuePreference mIPv6DNS2;

    private BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            initData();
        }
    };

    @Override
    public void onCreate(Bundle icicle) {
        super.onCreate(icicle);
        addPreferencesFromResource(R.xml.netstatus_info_settings);
        initView();
        initData();
    }


    private void initView() {
        mMACAddress = (ValuePreference) findPreference(KEY_MACADDRESS);
        mAddressType = (ValuePreference) findPreference(KEY_ADDRESSTYPE);
        mIPAddress = (ValuePreference) findPreference(KEY_IPADDRESS);
        mSubnetMask = (ValuePreference) findPreference(KEY_SUBNETMASK);
        mDefalutGateway = (ValuePreference) findPreference(KEY_DEFAULTGATEWAY);
        mDNSServer = (ValuePreference) findPreference(KEY_DNSSERVER);
        mADNSServer = (ValuePreference) findPreference(KEY_ADNSSERVER);
        mNATType = (ValuePreference) findPreference(KEY_NATTYPE);
        mVPNIP = (ValuePreference) findPreference(KEY_VPNIP);

        mIPv6Adress = (ValuePreference) findPreference(KEY_IPV6_ADDRESS);
        mIPv6Dns1 = (ValuePreference) findPreference(KEY_IPV6_DNS1);
        mIPv6DNS2 = (ValuePreference) findPreference(KEY_IPV6_DNS2);
    }

    private void initData() {
        try {
            mMACAddress.setShowValue(ConnectivityManager.getEthMac());
        } catch (Exception e) {
            e.printStackTrace();
        }
        NetworkConfigInfo currentNetworkInfo = ConnectivityManager.getCurrentNetworkInfo(getActivity());
        int connectType = getActiveConnectType();
        if (currentNetworkInfo != null) {
            // DHCP, PPPoE, Static IP
            if (!TextUtils.isEmpty(currentNetworkInfo.getType())) {
                if (currentNetworkInfo.getType().equals("DHCP")) {
                    if (connectType == ConnectivityManager.TYPE_WIFI) {
                        mAddressType.setShowValue(getResources().getString(
                                R.string.eth_connect_mod_DHCP));
                    } else {
                        mAddressType.setShowValue(getResources().getString(
                                R.string.eth_connect_mod_DHCP));
                    }
                } else if (currentNetworkInfo.getType().equals("Static IP")) {
                    if (connectType == ConnectivityManager.TYPE_WIFI) {
                        mAddressType.setShowValue(getResources().getString(
                                R.string.eth_connect_mod_static));
                    } else {
                        mAddressType
                                .setShowValue(getResources().getString(R.string.eth_connect_mod_static));
                    }
                } else {
                    mAddressType.setShowValue(currentNetworkInfo.getType());
                }
            }
            mIPAddress.setShowValue(currentNetworkInfo.getIp());
            mSubnetMask.setShowValue(currentNetworkInfo.getMask());
            mDefalutGateway.setShowValue(currentNetworkInfo.getGateway());
            mDNSServer.setShowValue(SystemProperties.get("net.dns1"));

            if (TextUtils.isEmpty(SystemProperties.get("net.dns1"))) {
                mDNSServer.setShowValue(getResources().getString(R.string.not_conf));
            } else {
                mDNSServer.setShowValue(SystemProperties.get("net.dns1"));
            }
            if (TextUtils.isEmpty(SystemProperties.get("net.dns2"))) {
                mADNSServer.setShowValue(getResources().getString(R.string.not_conf));
            } else {
                mADNSServer.setShowValue(SystemProperties.get("net.dns2"));
            }

            mIPv6Adress.setShowValue(currentNetworkInfo.getIpv6());
            mIPv6Dns1.setShowValue(currentNetworkInfo.getIpv6Dns1());
            mIPv6DNS2.setShowValue(currentNetworkInfo.getIpv6Dns2());

        }

        String nattype = NvramUtil.get("80");
        if (nattype == null || nattype.equals("")) {
            nattype = "Unknown NAT";
        }
        mNATType.setShowValue(nattype);

        String vpnIP = SystemProperties.get("net.vpn.ipaddress");
        if (vpnIP != null) {
            mVPNIP.setShowValue(vpnIP);
        }
    }


    /**
     * add by grandstream get network type
     *
     * @return
     */
    private int getActiveConnectType() {
        ConnectivityManager con = (ConnectivityManager)
                getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetInfo = con.getOriginalNetworkInfo();
        if (activeNetInfo != null && activeNetInfo.isConnectedOrConnecting()) {
            return activeNetInfo.getType();
        }
        return -1;
    }

    /**
     * add by jshluo 2018-09-18
     * when need onStop unregister receiver
     * need onResume registerReceiver
     *
     * */
    @Override
    public void onResume() {
        super.onResume();
        IntentFilter filter = new IntentFilter();
        filter.addAction(EthernetManager.NETWORK_STATE_CHANGED_ACTION);
        getActivity().registerReceiver(mReceiver, filter);
    }

    @Override
    public void onStop() {
        super.onStop();
        if(mReceiver != null) {
            getActivity().unregisterReceiver(mReceiver);
        }
    }
}

