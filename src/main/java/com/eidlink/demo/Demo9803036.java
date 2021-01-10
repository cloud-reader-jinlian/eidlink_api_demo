package com.eidlink.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Base64;

import com.eidlink.common.utils.SM2Util;
import com.eidlink.common.utils.StringUtil;
import com.eidlink.demo.utils.IOUtils;

import net.sf.json.JSONObject;

public class Demo9803036 {

	private static String url="http://192.168.1.24:8080/appserver/infovouche/sync/";//通常这个url后面会拼接cid或者是appid
	
	
	public static void main(String args[]) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, InvalidKeySpecException {
		SimpleDateFormat sf = new SimpleDateFormat("yyyyMMddHHmmss");
		Date date = new Date();
		String requestTime = sf.format(date);

		/**
		 * ${XXXX}此形式的参数是演示   有关于参数的详细说明 请看文档http://223.72.190.60:18181/docs/dev-standard/dev-standard-1clug7f2lectf
		 */
		String privatekey = "此处是示例私钥";
		String extension = ""; 
		String attach = ""; 
		String version = ""; 
		String cid = "";
		String bizType = "";
		String bizTime = "";
		String bizSequenceId = "";
		String sign = "";
		String qryType = "3";
		String reqID = "1490401537e4c1d0b22120094865422030675367fa";
		String algorithm_type = "0";// 0 代表ecb 1 cbc
		// --------------------获取所有的参数 结束------------------
		// ---------------------对公共参数参数处理开始----------
		extension = ""; // 对extension进行处理
		attach = ""; // 方便查看测试内容以及将响应数据
		version = "3.0.0";// 此接口必须是3.0.0
		bizTime = requestTime; // 业务处理时间
		bizSequenceId = UUID.randomUUID().toString().replace("-", ""); // 业务流水号
		// ---------------------对公共 参数处理结束 ---------------------
		// ----------------------拼装公共参数计算sign的json开始----------------
		JSONObject json = new JSONObject();
		json.element("extension", extension);
		json.element("attach", attach);
		json.element("version", version);
		json.element("cid", cid);
		json.element("biz_type", bizType);
		json.element("biz_time", bizTime);
		json.element("biz_sequence_id", bizSequenceId);
		// ----------------------拼装公共参数计算sign的json结束----------------
		// ---------------------拼装计算sign的私有参数json开始 -------------------
		json.element("reqID", reqID);
		json.element("qry_type", qryType);
		json.element("algorithm_type", algorithm_type);
		// ---------------------拼装计算sign的私有参数json结束 -------------------
		// ---------------------计算sign开始 ------------------
		String data = CreateLinkString(json).toString();// 拼接之后的参数
		sign = Base64.encodeBase64String((SM2Util.sign(data.getBytes(), Base64.decodeBase64(privatekey))));
		json.element("sign", sign);
		// ---------------------计算sign结束
		// 以上所有的参数已经拼接完成 请求接口
		String requestParam=json.toString();
		String result=doPostForHttp(requestParam, url+cid);
		System.out.println("result="+result);
	}

	/**
	 * 将对象的参数排序后 按照"a=1&b=2"的方式 拼接成字符串
	 * 
	 * @param jb
	 * @return "a=1&b=2"
	 */
	public static StringBuffer CreateLinkString(JSONObject jb) {

		StringBuffer sb = new StringBuffer();
		@SuppressWarnings("unchecked")
		List<String> keys = new ArrayList<String>(jb.keySet());
		Collections.sort(keys);
		int i = 0;
		for (Iterator<String> iterator = keys.iterator(); iterator.hasNext();) {
			String object = iterator.next();
			if ("sign".equals(object)) {
				continue;
			}
			if ("app_key".equals(object)) {
				continue;
			}
			String v = jb.get(object).toString();

			if (!StringUtil.isNullOrEmpty(v) && !"null".equals(v.toLowerCase())) {
				if (v.startsWith("{") && v.endsWith("}")) {
					JSONObject jb2 = JSONObject.fromObject(jb.get(object));
					v = CreateLinkString(jb2).toString();
				}
				if (i != 0) {
					sb.append("&");
				}
				sb.append(object).append("=").append(v);
				i++;
			}
		}
		System.out.println(" CreateLinkString  end");
		return sb;
	}

	/**
	 * 发送HTTP/POST请求
	 *
	 * @param request 请求参数
	 * @param url     请求地址
	 * @return
	 * @throws Exception
	 */
	public static String doPostForHttp(String request, String burl) {
		URL url = null;
		HttpURLConnection urlConnection = null;
		// Read server's response
		InputStream inputStream = null;
		OutputStreamWriter out = null;
		String body = "";
		try {
			url = new URL(burl);
			urlConnection = (HttpURLConnection) url.openConnection();
			urlConnection.setDoOutput(true);
			urlConnection.setRequestProperty("idsp-protocol-version", "2.0.0");
			urlConnection.setRequestProperty("content-type", "application/json");
			urlConnection.setRequestProperty("charset", "UTF-8");
			urlConnection.setRequestProperty("Accept-Charset", "utf-8");

			out = new OutputStreamWriter(urlConnection.getOutputStream(), "utf-8");
			out.write(request);
			out.flush();
			String encoding = urlConnection.getContentEncoding();
			if (urlConnection.getResponseCode() == 500) {
				inputStream = urlConnection.getErrorStream();
				body = IOUtils.toString(inputStream, encoding);
			} else {
				inputStream = urlConnection.getInputStream();
				body = IOUtils.toString(inputStream, encoding);
			}

			// body = IOUtils.toString(inputStream, encoding);
		} catch (MalformedURLException e) {
			e.printStackTrace();

			JSONObject result = new JSONObject();
			result.put("result", "04");
			result.put("result_detail", "0401006");
			body = result.toString();
		} catch (IOException e) {
			e.printStackTrace();
			JSONObject result = new JSONObject();
			result.put("result", "04");
			result.put("result_detail", "0401006");
			body = result.toString();
		} finally {
			try {
				if (null != inputStream) {
					inputStream.close();
				}
				if (null != out) {
					out.close();
				}
			} catch (IOException e) {
			}
		}

		return body;
	}

	/**
	 * 发送HTTPS/POST请求
	 *
	 * @param request 请求参数
	 * @param url     请求地址
	 * @return
	 * @throws Exception
	 */
	public static String doPostForHttps(String request, String burl) {

		String result = "";
		PrintWriter out = null;
		BufferedReader in = null;
		HttpURLConnection conn;

		try {
			trustAllHosts();
			URL realUrl = new URL(burl);
			// 通过请求地址判断请求类型(http或者是https)
			if (realUrl.getProtocol().toLowerCase().equals("https")) {
				HttpsURLConnection https = (HttpsURLConnection) realUrl.openConnection();
				https.setHostnameVerifier(DO_NOT_VERIFY);
				conn = https;
			} else {
				conn = (HttpURLConnection) realUrl.openConnection();
			}
			// 设置通用的请求属性
			conn.setRequestProperty("accept", "*/*");
			conn.setRequestProperty("connection", "Keep-Alive");
			conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
			conn.setRequestProperty("Content-Type", "application/json;charset=utf-8");
			// 发送POST请求必须设置如下两行
			conn.setDoOutput(true);
			conn.setDoInput(true);
			// 获取URLConnection对象对应的输出流
			out = new PrintWriter(conn.getOutputStream());
			// 发送请求参数
			out.print(request);
			// flush输出流的缓冲
			out.flush();
			// 定义BufferedReader输入流来读取URL的响应
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			while ((line = in.readLine()) != null) {
				result += line;
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {// 使用finally块来关闭输出流、输入流
			try {
				if (out != null) {
					out.close();
				}
				if (in != null) {
					in.close();
				}
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return result;
	}

	private static void trustAllHosts() {
		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return new java.security.cert.X509Certificate[] {};
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) {
			}
		} };
		// Install the all-trusting trust manager
		try {
			SSLContext sc = SSLContext.getInstance("TLSv1.2");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private final static HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};

}
