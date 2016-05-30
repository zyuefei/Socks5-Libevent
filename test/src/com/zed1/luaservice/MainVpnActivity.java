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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.Toast;

@SuppressLint("SdCardPath")
public class MainVpnActivity extends Activity {

	protected Handler mHandler = new Handler() {

		public void handleMessage(Message message) {
			Intent intent;
			switch (message.what) {
			case 0:
				Toast.makeText(MainVpnActivity.this, "安装可执行文件出错",
						Toast.LENGTH_LONG).show();
				break;
			case 1:
				/**
				 * 启动服务
				 * 
				 * 
				 */
				startService(new Intent(MainVpnActivity.this,
						MainVpnService.class));
				break;
			case 2:
				Log.d("<<<---", "start " + (String) message.obj);
				intent = new Intent("com.zed1.luaservice.START");
				intent.putExtra("params", (String) message.obj);
				sendBroadcast(intent);
				break;
			case 3:
				Toast.makeText(MainVpnActivity.this, "没有出口", Toast.LENGTH_LONG)
						.show();
				break;
			}
		}

	};

	protected BroadcastReceiver mReceiver = new BroadcastReceiver() {

		public void onReceive(Context context, Intent intent) {
			Toast.makeText(MainVpnActivity.this,
					intent.getIntExtra("STATE", 0) != 0 ? "连接成功" : "连接断开",
					Toast.LENGTH_LONG).show();
		}

	};

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		/**
		 * 发起建立 VPN 请求
		 * 
		 * 
		 */
		Intent intent = VpnService.prepare(MainVpnActivity.this);

		if (intent != null)
			startActivityForResult(intent, 0);
		registerReceiver(mReceiver, new IntentFilter(
				"com.zed1.luaservice.STATE"));

		setContentView(R.layout.activity_main);

		((Button) findViewById(R.id.button1))
				.setOnClickListener(new OnClickListener() {

					@Override
					public void onClick(View v) {
						getParams();
					}

				});

		/**
		 * 把可执行文件释放到运行目录中去
		 * 
		 * 
		 */

		new Thread(new Runnable() {

			@Override
			public void run() {
				String[] ll = new String[] { "tun2socks", "client",
						"whitelist.txt" };
				String[] fl = new File("/data/data/com.zed1.luaservice/")
						.list();

				int j;

				for (int i = 0; i < ll.length; i++) {
					for (j = 0; j < fl.length; j++) {
						if (ll[i].equals(fl[j])) {
							break;
						}
					}
					if (j == fl.length)
						try {
							InputStream is = getAssets().open(ll[i]);
							FileOutputStream os = new FileOutputStream(
									"/data/data/com.zed1.luaservice/" + ll[i]);
							int c;
							while ((c = is.read()) != -1) {
								os.write(c);
							}
							is.close();
							os.close();

						} catch (IOException e) {
							mHandler.sendEmptyMessage(0);
							return;
						}
				}
				mHandler.sendEmptyMessage(1);
			}

		}).start();
	}

	protected void getParams() {
		new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					Log.d("<<<---",
							"get http://202.109.165.79:9000/manage/cgi/api!getDeviceList.action?status=1");

					JSONArray a = new JSONObject(
							EntityUtils
									.toString(new DefaultHttpClient()
											.execute(
													new HttpGet(
															"http://202.109.165.79:9000/manage/cgi/api!getDeviceList.action?status=1"))
											.getEntity()))
							.getJSONArray("device_list");
					JSONObject p = null;
					String uid = null;

					/**
					 * 找到一个和上次不一样的配置
					 * 
					 * 
					 */
					{
						SharedPreferences preference = getSharedPreferences(
								"last_uid", Activity.MODE_PRIVATE);
						String last_uid = preference.getString("uid", "");
						int i = 0;
						for (; i < a.length(); i++) {
							if (!a.getJSONObject(i).getString("uid")
									.equals(last_uid)) {
								break;
							}
						}
						if (i < a.length()) {
							p = a.getJSONObject(i);
						} else {
							p = a.getJSONObject(0);
						}
						uid = p.getString("uid");
						Editor editor = preference.edit();
						editor.putString("uid", uid);
						editor.commit();
					}

					String[] turn_server = p.getString("turn_server")
							.split(":");
					String[] relay_info = p.getString("relay_info").split(":");
					/**
					 * 不检查服务器返回参数
					 * 
					 * 
					 */
					Message message = new Message();
					message.obj = "-s " + turn_server[0] + " -p "
							+ turn_server[1] + " -r " + relay_info[0] + " -l "
							+ relay_info[1];
					message.what = 2;
					mHandler.sendMessage(message);
					return;
				} catch (ClientProtocolException e) {
				} catch (IOException e) {
				} catch (ParseException e) {
				} catch (JSONException e) {
				}
				mHandler.sendEmptyMessage(3);
			}

		}).start();
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
		unregisterReceiver(mReceiver);
	}

	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		if (resultCode == Activity.RESULT_OK) {
			/**
			 * 代理中需要填的参数有
			 * 
			 * -r 127.0.0.1 -l 8889 -s 203.156.199.168 -p 5000
			 * 
			 */
			String params = getIntent().getStringExtra("params");

			if (params != null) {
				Log.d("<<<---", "start(prepared)" + params);

				Intent intent = new Intent("com.zed1.luaservice.START");
				intent.putExtra("params", params);
				sendBroadcast(intent);
			}
		}
	}

}
