package main;

import org.jsoup.Connection;
import org.jsoup.Jsoup;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Created by 炜贤 on 2016/4/4.
 * 连接QLSC_STU
 */
public class Connect {
    static String username = "201400301074";
    static String password = "094534";

    public Map<String, String> loadCookie(Connection.Response response, String username, String password) {
        Map<String, String> map = response.cookies();
        map.put("filterFlag", "false");
        map.put("hello1", username);
        map.put("hello2", "true");
        map.put("hello5", "");
        map.put("hello3", encryptPwd(password));
        return map;
    }

    /**
     * 异或处理密码
     *
     * @return
     */
    private String encryptPwd(String password) {
        //TODO 异或处理密码
        String result = "";
        char temp[] = new char[password.length()];
        for (int i = 0; i < password.length(); i++) {
            temp[i] = (char) (password.charAt(i) ^ 0xff);
            result += temp[i];
        }
        return result;
    }

    /**
     * 加载要发送的数据
     *
     * @param html
     * @param username
     * @param password
     * @return
     */
    public Map<String, String> loadData(String html, String username, String password, boolean isLogin) {
        Map<String, String> map = new HashMap<>();
        InetAddress address = null;
        try {
            address = InetAddress.getLocalHost();
            String ip = address.getHostAddress();
            map.put("Language", "Chinese");
            map.put("ClientIP", ip);
            String str = "<input type=\"hidden\" name=sessionID value=";
            int index = html.indexOf(str) + str.length();
            //获取sessionID
            String sessionID = html.substring(index, index + 20);
            if (sessionID.contains(">")) {
                sessionID = sessionID.substring(0, sessionID.length() - 1);
            }
            map.put("sessionID", sessionID);
            map.put("timeoutvalue", "45");
            map.put("heartbeat", "240");
            long startTime = System.currentTimeMillis();
            map.put("StartTime", String.valueOf(startTime));
            map.put("username", username);
            map.put("password", password);
            map.put("shkOvertime", "720");
            map.put("strOldPrivateIP", ip);
            map.put("strOldPublicIP", ip);
            map.put("strPrivateIP", ip);
            map.put("PublicIP", ip);
            map.put("iIPCONFIG", "0");
            if (isLogin) {
                map.put("fastwebornot", "false");
                map.put("sHttpPrefix", "http://192.168.8.10");
            } else {
                map.put("myaction", "0");
                map.put("linkStatues", "1");
                map.put("strUserPortNo", "CC3-H3CWX5002-vlan-01-0024@vlan-SSID-QLSC_STU@SSID");
                long temp = 100;
                map.put("iTimeStamp", String.valueOf(startTime - temp));
                map.put("iUserStatus", "99");
            }

            return map;
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获得连接
     *
     * @param mainURL
     * @return
     * @throws IOException
     */
    private Connection.Response getResponse(String mainURL) throws IOException {
        Connection.Response response = Jsoup.connect(mainURL).ignoreContentType(true)
                .header("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; InfoPath.3; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)")
                .header("Accept-Encoding", "gzip, deflate").header("Host", "192.168.8.10").header("Connection", "Keep-Alive").header("Accept", "*/*")
                .header("Accept-Language", "zh-Hans-CN,zh-Hans;q=0.5")
                .method(Connection.Method.GET).execute();
        return response;
    }

    public Connection loadHeaders(String url) {
        Connection connection = Jsoup.connect(url).ignoreContentType(true).method(Connection.Method.POST)
                .header("Accept", "image/gif, image/jpeg, image/pjpeg, application/x-ms-application, application/xaml+xml, application/x-ms-xbap, */*")
                .header("Referer", "http://192.168.8.10/portal/index_default.jsp?Language=Chinese").header("Accept-Language", "zh-Hans-CN,zh-Hans;q=0.5")
                .header("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; InfoPath.3; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)")
                .header("Content-Type", "application/x-www-form-urlencoded").header("Accept-Encoding", "gzip, deflate").header("Host", "192.168.8.10")
                .header("Connection", "Keep-Alive").header("Cache-Control", "no-cache");
        return connection;
    }

    /**
     * 登录
     *
     * @param mainURL
     * @param loginURL
     */
    public void login(String mainURL, String loginURL) {

        try {
            Connection.Response response = getResponse(mainURL);

            String loginResult = loadHeaders(loginURL).cookies(loadCookie(response, username, password))
                    .data(loadData(response.body(), username, password, true)).execute().body();

            System.out.println(loginResult);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 登出
     *
     * @param mainURL
     * @param logoutURL
     */
    public void logout(String mainURL, String logoutURL) {
        try {
            String result = loadHeaders(logoutURL).cookies(loadCookie(getResponse(mainURL), username, password))
                    .data("Submit1", "断 开").data(loadData(getResponse(mainURL).body(), username, password, false))
                    .execute().body();
            System.out.println(result);
            String result2 = loadHeaders(logoutURL).cookies(loadCookie(getResponse(mainURL), username, password))
                    .data("Submit1", "确定").data(loadData(getResponse(mainURL).body(), username, password, false))
                    .execute().body();
            System.out.println(result2);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String mainURL = "http://192.168.8.10/portal/index_default.jsp?Language=Chinese";
        String loginURL = "http://192.168.8.10/portal/login.jsp?Flag=0";
        String logoutURL = "http://192.168.8.10/portal/logout.jsp";

        Connect connect = new Connect();


        TimerTask task = new TimerTask() {
            @Override
            public void run() {
//                try {
//                    connect.login(mainURL, loginURL);
//                    Thread.sleep(500);
//                    connect.logout(mainURL, logoutURL);
//                } catch (InterruptedException e) {
//                    e.printStackTrace();
//                }
                connect.logout(mainURL, logoutURL);
            }
        };
        task.run();

    }

}
