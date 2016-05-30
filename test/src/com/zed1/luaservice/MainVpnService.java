// +----------------------------------------------------------------------
// | ZYSOFT [ MAKE IT OPEN ]
// +----------------------------------------------------------------------
// | Copyright(c) 20015 ZYSOFT All rights reserved.
// +----------------------------------------------------------------------
// | Licensed( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author:zy_cwind<391321232@qq.com>
// +----------------------------------------------------------------------

package com.zed1.luaservice;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

@SuppressLint("SdCardPath")
public class MainVpnService extends VpnService implements Runnable {

	boolean mRunning;

	/**
	 * 全局侦听器，用于启停代理
	 * 
	 */
	BroadcastReceiver mainVpnServiceReceiver = new BroadcastReceiver() {

		/**
		 * 服务被启动后长期在后台运行
		 * 
		 * 
		 */
		@Override
		public void onReceive(Context context, Intent intent) {
			String action = intent.getAction();
			Log.d("<<<---", "receive " + action);

			if (action.equals("com.zed1.luaservice.START")) {
				if (mRunning)
					stop();
				start(intent.getStringExtra("params"));
			} else {
				stop();
			}
		}

	};

	Process p1 = null;
	Process p2 = null;

	/**
	 * VPN 连接
	 * 
	 */
	ParcelFileDescriptor conn = null;

	Thread vpnThread = null;
	LocalServerSocket vpnThreadSocket = null;
	boolean vpnThreadRunning;

	/**
	 * 代理客户端命令行参数 -r 127.0.0.1 -l 8889 -s 203.156.199.168 -p 5000
	 * 
	 * 
	 */
	public void startShadowsocksDeamon(String params) {
		try {
			p1 = new ProcessBuilder()
					.command(
							("/data/data/com.zed1.luaservice/client -b 127.0.0.1 -i 1080 " + params)
									.split(" ")).redirectErrorStream(true)
					.start();
		} catch (IOException e) {
			Log.d("<<<---", "unable to start client");
		}
	}

	public int startVpn() {
		/**
		 * 建立 VPN 链接，操作会创建一个 TUN 设备，地址是26.26.26.1，子网掩码是255.255.255.0
		 * 添加一个路由，所有的数据包都转发至该 TUN 设备
		 * 
		 * 
		 */
		conn = new Builder().addAddress("26.26.26.1", 24)
				.addRoute("0.0.0.0", 0).addRoute("8.8.0.0", 16).setMtu(1500)
				.establish();

		if (conn == null) {
			Log.d("<<<---", "unable to start vpn");
			return -1;
		}

		int fd = conn.getFd();

		/**
		 * 此处对 DNS 不进行代理
		 * 
		 * 
		 */
		try {
			p2 = new ProcessBuilder()
					.command(
							String.format(
									"/data/data/com.zed1.luaservice/tun2socks --netif-ipaddr 26.26.26.2 --netif-netmask 255.255.255.0 --socks-server-addr 127.0.0.1:1080 --tunfd %d --tunmtu 1500 --loglevel 3 --enable-udprelay",
									fd).split(" ")).redirectErrorStream(true)
					.start();

		} catch (IOException e) {
			Log.d("<<<---", "unable to start tun2socks");
		}
		return fd;
	}

	public void start(String params) {

		/**
		 * 确保已经请求 VPN
		 * 
		 * 
		 */
		if (VpnService.prepare(this) != null) {
			Intent intent = new Intent(this, MainVpnActivity.class);
			intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

			/**
			 * 调起 ACTIVITY 在获取了 VPN 权限之后自动启动代理
			 * 
			 * 
			 */
			intent.putExtra("params", params);
			startActivity(intent);
			return;
		}

		/**
		 * 修改二进制文件为可执行
		 * 
		 * 
		 */
		try {

			new ProcessBuilder()
					.command(
							"/system/bin/chmod 755 /data/data/com.zed1.luaservice/tun2socks"
									.split(" ")).redirectErrorStream(true)
					.start();

			new ProcessBuilder()
					.command(
							"/system/bin/chmod 755 /data/data/com.zed1.luaservice/client"
									.split(" ")).redirectErrorStream(true)
					.start();
		} catch (IOException e) {
			Log.d("<<<---", "chmod failed");
		}

		vpnThread = new Thread(this);
		vpnThread.start();

		startShadowsocksDeamon(params);
		int fd = startVpn();

		if (fd != -1) {

			/**
			 * TUN2SOCKS启动后将 VPN 文件描述符发送过去，在参数中设置是不奏效的
			 * 
			 * 
			 */
			for (int i = 0; i < 5000; i += 1000) {
				try {
					Thread.sleep(i);
					if (com.zed1.proxy.System.sendfd(fd) != -1) {
						Intent intent = new Intent("com.zed1.luaservice.STATE");
						intent.putExtra("STATE", 1);
						sendBroadcast(intent);
						mRunning = true;
						return;
					}
				} catch (InterruptedException e) {
				}
			}
		}

		stop();
	}

	public void stop() {
		/**
		 * 关闭后台进程
		 * 
		 * 
		 */
		if (vpnThread != null) {
			vpnThreadRunning = false;
			try {
				vpnThreadSocket.close();
			} catch (IOException e) {
			}
			vpnThread = null;
		}

		if (p1 != null) {
			p1.destroy();
			p1 = null;
		}
		if (p2 != null) {
			p2.destroy();
			p2 = null;
		}

		/**
		 * 关闭 VPN 连接
		 * 
		 * 
		 */
		if (conn != null) {
			try {
				conn.close();
			} catch (IOException e) {
			}
			conn = null;
		}
		Intent intent = new Intent("com.zed1.luaservice.STATE");
		intent.putExtra("STATE", 0);
		sendBroadcast(intent);
		mRunning = false;
	}

	@Override
	public void onCreate() {
		android.os.Debug.waitForDebugger();

		super.onCreate();

		/**
		 * 注册一个全局广播消息接收器
		 * 
		 * 
		 */
		IntentFilter filter = new IntentFilter();
		filter.addAction("com.zed1.luaservice.START");
		filter.addAction("com.zed1.luaservice.STOP");
		registerReceiver(mainVpnServiceReceiver, filter);

		new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					LocalSocket localSocket = new LocalSocket();
					localSocket.bind(new LocalSocketAddress(
							"/data/data/com.zed1.luaservice/luaservice_path",
							LocalSocketAddress.Namespace.FILESYSTEM));

					LocalServerSocket server = new LocalServerSocket(
							localSocket.getFileDescriptor());

					boolean running = true;
					while (running) {
						LocalSocket socket = server.accept();
						BufferedReader reader = new BufferedReader(
								new InputStreamReader(socket.getInputStream()));
						String params = reader.readLine();
						if (params.startsWith("START")) {
							String[] p = params.split(",");
							if (p.length == 5) {
								start("-r " + p[1] + " -l " + p[2] + " -s "
										+ p[3] + " -p " + p[4]);
								socket.getOutputStream()
										.write(mRunning ? 1 : 0);
							}
						} else if (params.startsWith("STOP")) {
							stop();
							socket.getOutputStream().write(mRunning ? 1 : 0);
						}
					}

					localSocket.close();
				} catch (IOException e) {
				}
			}

		}).start();

		Log.d("<<<---", "service created");
	}

	/**
	 * 代理中创建的链接不能走 VPN 形成环路，启动一个线程对代理中的 SOCKET 进行设置
	 * 
	 * 
	 */
	@Override
	public void run() {

		try {
			LocalSocket b = new LocalSocket();
			b.bind(new LocalSocketAddress(
					"/data/data/com.zed1.luaservice/protect_path",
					LocalSocketAddress.Namespace.FILESYSTEM));

			vpnThreadSocket = new LocalServerSocket(b.getFileDescriptor());
			vpnThreadRunning = true;
			/**
			 * 启动接收
			 * 
			 */
			while (vpnThreadRunning) {
				LocalSocket l = vpnThreadSocket.accept();
				InputStream is = l.getInputStream();
				is.read();
				FileDescriptor[] fds = l.getAncillaryFileDescriptors();

				if (fds != null && fds.length != 0) {
					try {
						/**
						 * 通过反射获取了文件描述符的 INT 值
						 * 
						 * 
						 */
						int fd = (Integer) fds[0].getClass()
								.getDeclaredMethod("getInt$").invoke(fds[0]);
						OutputStream os = l.getOutputStream();

						/**
						 * 将代理使用的 SOCKET 分离出来，从而走默认的网关
						 * 
						 * 
						 */
						os.write(protect(fd) ? 0 : 1);
						com.zed1.proxy.System.jniclose(fd);
						os.close();
					} catch (Exception e) {
					}
				}
				is.close();
			}

			b.close();
		} catch (IOException e) {
		}
	}

	@Override
	public void onRevoke() {
		/**
		 * 防止VPN 服务关闭时销毁服务
		 * 
		 */
		stop();
	}
}
