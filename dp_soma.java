package testjenkins;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.TopLevelItem;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Hudson;
import hudson.model.Job;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.model.TaskListener;
import hudson.util.StreamTaskListener;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import java.util.ResourceBundle;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;

import net.sf.json.JSONObject;

import org.apache.commons.codec.binary.Base64;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
/*
=======================================================================================================================================================
Author: Saptarshi Mandal. IBM
Date:   Sep 29, 2015
Version: V.3.0
Description: Jenkins Plugin for DataPower automated deployment and continuous integration.
Change History: 
Initial version. V.1.0
- Mandal, Saptarshi- - 29-Sep-2015

Updated the parameters.properties.
- Mandal, Saptarshi- - 29-Sep-2015

Soap management file for importing objects to DataPower.
Updated the source type to accept XML format.
Updated the code for Encoding.
Updated the current SOMA uri to legacy URI to support multiple object import.
Added file writer to write the encoded value to the XML file.
Add the encoded string to a file for SOMA call.
Updated the code to Create the Import_Object.xml file after getting the encoded value.
- Mandal, Saptarshi - 30-Sep-2015

Updated the code with with the config of .jelly for Jenkins plugin.
Updated the code to take XCFG files from workspace.
Added the connections.
- Mandal, Saptarshi - 06-Oct-2015

Removed type Builder.
Jenkin plugin source code for DP deployment.
- Mandal, Saptarshi - 08-Oct-2015

Removed user - Mandal, Saptarshi - 09-Oct-2015

Jenkins Plugin for DataPower deployment.
Added index.jelly and properties file.
Added config and global jelly files.
Referenced global config setup to local config.
Updated the pom file with proper name.
Removed unnecessary code.
Removeing unused code to reflect proper path in pom.xml
Working code for the plugin.
- Mandal, Saptarshi - 16-Oct-2015

Added flushing of stylesheet cache and save configuration functionality after each deployment.
Added user name and passwor field in the global configuration, so that we can pass the credentials at the time of build.
- Mandal, Saptarshi - 19-Oct-2015

Added debug in the code.
Updated the code to get the directory path from custom workspace instead of properties file.
Added logging capability to display information in Jenkins console.
- Mandal, Saptarshi - 20-Oct-2015

Domain details has been moved from global config to build config. - Mandal, Saptarsh - 21-Oct-2015

Added special characters between logs.
Stacktrace has been added for the out put from DataPower.
Updated stacktrace login for DataPower Failure.
Updated the POM file.
- Mandal, Saptarshi - 22-Oct-2015

Updated the code so that deployment policy gets deployed before the object.
Updated the code to create different SOMA scripts for deployment policy and object import. Also removed device name setup from build config.
Updated the login info in the code.
- Mandal, Saptarshi - 01-Dec-2015 17:20

Space added before the location.
Updated the code to traverse DeploymentPolicy & ServiceExport under _dp folder. Also selects the deployment policy for the domain which has been selected from Jenkins.
Updated the plugin to to continue its job even if it doesn't find files/folders in some _dp folders & changed the directory location of the Import_Object.xml to be created.
Updated the log presentation for the GUI console and cleanup.
- Mandal, Saptarshi - 02-Dec-2015
=======================================================================================================================================================
*/
public class dp_soma extends Builder {
	private static PrintStream logStream = null;
	private String name;
	private String domain;
	private String policyFile;
	private AbstractBuild build;

	// Fields in config.jelly must match the parameter names in the
	// "DataBoundConstructor"
	@DataBoundConstructor
	public dp_soma(String name, String domain) {
		this.name = name;
		this.domain = domain;
		debug(domain);
	}

	public void setName(String name) {
		this.name = name;
	}

	/**
	 * We'll use this from the <tt>config.jelly</tt>.
	 */
	public String getName() {
		return name;

	}

	private static Properties param = new Properties();
	// Code to Allow Opening insecure HTTPS Connection
	// Allowing all DataPower XML Management Interface Cert to create Connection
	// without it's validation
	static {
		try {
			TrustManager[] trustAllCerts = { new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				public void checkClientTrusted(X509Certificate[] certs,
						String authType) {
				}

				public void checkServerTrusted(X509Certificate[] certs,
						String authType) {
				}
			} };
			SSLContext sc = SSLContext.getInstance("SSL");

			HostnameVerifier hv = new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			};
			sc.init(null, trustAllCerts, new SecureRandom());
			HttpsURLConnection
					.setDefaultSSLSocketFactory(sc.getSocketFactory());
			HttpsURLConnection.setDefaultHostnameVerifier(hv);
		} catch (Exception exception) {
			System.err.println(exception);
		}
	}

	/**
	 * @param args
	 */

	private static final String POL = "_Policy";

	private void doIt(File file, javaPostToDatapower connections)// throws
																	// FormException
	{
		doIt2(file, connections, "_Policy.xcfg", false);
		doIt2(file, connections, ".xcfg", true);
	
	}
	
	private boolean checkDir( File file ){
		if( !file.exists()){
			logStream.println("[ERROR] "+file.getAbsolutePath() +" - is not found!");
			logStream.println("[INFO] *************************************************************************************************************");
			return false;
		}
		if( !file.canRead()){
			logStream.println("[ERROR] "+file.getAbsolutePath() +" - is not readable!");
			logStream.println("[INFO] *************************************************************************************************************");
			return false;
		}
		if( !file.isDirectory()){
			logStream.println("[ERROR] "+file.getAbsolutePath() +" - is not a directory!");
			logStream.println("[INFO] *************************************************************************************************************");
			return false;
		}
		return true;
	}

	private void doIt2(File file, javaPostToDatapower connections, String ext,
			boolean check)// throws FormException
	{
		if( !checkDir( file)){
			
			return;
		}
		
		if( check ) {
			// No config file
			String path = file.getAbsolutePath();
			path += file.separator;
			path += "ServiceExport";
			logStream.println("[INFO] Service export directory path - "+path);
			file = new File( path);
		}
		else {
			String path = file.getAbsolutePath();
			path += file.separator;
			path += "DeploymentPolicy";
			logStream.println("[INFO] Deployment policy directory path - "+path);
			file = new File( path);
		}
if( !checkDir( file)){
			
			return;
		}
		boolean found = false;
		File[] files = file.listFiles();
		for (int i = 0; i < files.length; i++) {
			if (!files[i].isDirectory()) {
				if (files[i].getName().endsWith(ext) ) {
					if( !check && !files[i].getName().startsWith(domain) ) continue;
					
					if (check && files[i].getName().endsWith(POL + ext))
						continue;
					if( !check)policyFile=files[i].getName();

					try {
						found = true;
						logStream.println("[INFO] *************************************************************************************************************");
						logStream.println("[INFO] ");
						logStream.println("[INFO] " + files[i].getName()
								+ " - file found! ");
						logStream.println("[INFO] @ " + file.getAbsolutePath());

						readAll(files[i].getAbsolutePath(), connections, check);
					} catch (Exception e) {
						logStream.println("[INFO] ");
						e.printStackTrace(logStream);
					}
				}
			}
		}
		if (!found) {
			// TaskListener taskListener=StreamTaskListener.fromStdout();
			// PrintStream ps= taskListener.getLogger();
			logStream.println("[INFO] *************************************************************************************************************");
			logStream.println("[INFO] ");
			logStream.println("[INFO] No config file found to read - "
					+ file.getAbsolutePath());
		}
	}

	public static String getParam(String paramName) {
		return param.getProperty(paramName);
	}

	private void readParameters() {

		try {
			InputStream is = this.getClass().getResourceAsStream(
					"parameters.properties");
			debug("is1 = " + is);
			URL rs = getClass().getClassLoader().getResource(
					"parameters.properties");

			debug("rs = " + rs);
						is = rs.openConnection().getInputStream();
			param.load(is);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			logStream.println("[INFO] ");
			e.printStackTrace(logStream);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			logStream.println("[INFO] ");
			e.printStackTrace(logStream);
		}

	}
	private String buildBefore() {
		// TODO Auto-generated method stub
		int index = BEFORE3.indexOf("POS");
		int ind = policyFile.lastIndexOf(".");
		String fName = policyFile.substring(0, ind);
		String val = BEFORE3.substring(0, index)+fName+BEFORE3.substring(index+3);
		return val;
	}
	private static final String BEFORE1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			+ "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">"
			+ "<env:Body>"
			+ "<dp:request xmlns:dp=\"http://www.datapower.com/schemas/management\" domain=\"";
	private static final String BEFORE2 = "\">"
			+ "<dp:do-import source-type=\"XML\" overwrite-objects=\"true\" overwrite-files=\"true\">";
	private static final String BEFORE3 = "\">"
			+ "<dp:do-import source-type=\"XML\" overwrite-objects=\"true\" overwrite-files=\"true\" deployment-policy=\"POS\">";
	// private static final String AFTER = "</dp:do-import>" + "</dp:request>"
	// + "</env:Body>" + "</env:Envelope>";
	private static final String AFTER = "</dp:do-import>"
			+ "</dp:request>"
			+ "<dp:request xmlns:dp=\"http://www.datapower.com/schemas/management\">"
			+ "<dp:do-action>"
			+ "<FlushStylesheetCache>"
			+ "<XMLManager>default</XMLManager>"
			+ "</FlushStylesheetCache>"
			+ "</dp:do-action>"
			+ "</dp:request>"
			+ "<dp:request xmlns:dp=\"http://www.datapower.com/schemas/management\">"
			+ "<dp:do-action>" + "<SaveConfig/>" + "</dp:do-action>"
			+ "</dp:request>" + "</env:Body>" + "</env:Envelope>";

	private void readAll(String path, javaPostToDatapower connections, boolean noPolicyFile)
			throws Exception {
		String dir  = build.getWorkspace().toURI().getPath();
		File file = new File(dir+"/Import_Object.xml");
		logStream.println("[INFO] ");
		logStream.println("[INFO] Reading the file...............");

		PrintStream ps = null;
		BufferedReader br = null;
		try {
			FileOutputStream fos = new FileOutputStream(file);
			ps = new PrintStream(fos);

			br = new BufferedReader(new FileReader(path));
			
			if( noPolicyFile){
				String before = buildBefore();
				debug(BEFORE1 + domain + before);
				ps.println(BEFORE1 + domain + before);
			}else{
				debug(BEFORE1 + domain + BEFORE2);
				ps.println(BEFORE1 + domain + BEFORE2);
			}
			
			logStream.println("[INFO] ");
			logStream
					.println("[INFO] Started creating the script for deployment - "
							+ file);

			StringBuilder content = new StringBuilder();

			BufferedReader rd = new BufferedReader(new FileReader(path));

			while (true) {
				String row = rd.readLine();
				if (row == null)
					break;
				content.append(row);

			}
			rd.close();
			logStream.println("[INFO] ");
			logStream.println("[INFO] Source XCFG is getting converted to base64. ");

			byte[] bytesEncoded = Base64.encodeBase64(content.toString()
					.getBytes());
			// System.out.println("Ecncoded value is");
			// System.out.println(new String(bytesEncoded));

			ps.print("<dp:input-file>");
			ps.print(new String(bytesEncoded));
			ps.println("</dp:input-file>");
			logStream.println("[INFO] ");
			logStream.println("[INFO] Finished converting!");
			
			ps.println(AFTER);
			logStream.println("[INFO] ");
			logStream
					.println("[INFO] Script ready for deployment - "
							+ file);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			logStream.println("[INFO] ");
			e.printStackTrace(logStream);
		} finally {
			try {
				if (br != null)
					br.close();
				if (ps != null) {
					ps.close();
					logStream.println("[INFO] ");
					logStream.println("[INFO] Connecting to DataPower...............");
					logStream.println("[INFO] ");
					logStream.println("[INFO] Connected!");
					logStream.println("[INFO] ");
					logStream
							.println("[INFO] Start processing the script for deployment.");
					String url = DescriptorImpl.getUrl();
					String user = DescriptorImpl.getUser();
					String password = DescriptorImpl.getPassword();
					logStream.println("[INFO] ");
					logStream.println("[INFO] Do not close this window. Deployment is in progress...............");
										

					debug("url = " + url);
					String output = sendRequest(url,
							dir +"/Import_Object.xml", user, password);
					System.out.println(output);

					logStream.println("[INFO] ");
					logStream.println(output);
					logStream.println("[INFO] ");
					logStream.println("[INFO]  Job done!!");
					logStream.println("[INFO] *************************************************************************************************************");

				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				logStream.println("[INFO] ");
				e.printStackTrace(logStream);
				logStream.println("[INFO] *************************************************************************************************************");
			}
		}
	}



	/**
	 * Send GetFileStore Request with location "local:" to DataPower box to file
	 * local file system
	 * 
	 * @param pUrl
	 * @param pXmlFile2Send
	 * @param pDomain
	 * @param pUsername
	 * @param pPassword
	 * @return
	 * @throws Exception
	 * 
	 */

	public static String sendRequest(String pUrl, String pXmlFile2Send,
			String pUsername, String pPassword) throws Exception {
		String SOAPUrl = pUrl;
		String xmlFile2Send = pXmlFile2Send;
		String SOAPAction = "";

		// Create the connection where we're going to send the file.
		URL url = new URL(SOAPUrl);
		URLConnection connection = url.openConnection();
		HttpsURLConnection httpConn = (HttpsURLConnection) connection;

		// Open the input file. After we copy it to a byte array, we can see how
		// big it is so that we can set the HTTP Content-Length property.
		FileInputStream fin = new FileInputStream(xmlFile2Send);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		// Copy the SOAP file to the open connection.
		copy(fin, bout);
		fin.close();

		// Replace domainName in Request
		String soapRequest = bout.toString();

		// Convert into bytes
		byte[] b = soapRequest.getBytes();

		// Set the appropriate HTTP parameters.
		httpConn.setRequestProperty("Content-Length", String.valueOf(b.length));
		httpConn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
		httpConn.setRequestProperty("SOAPAction", SOAPAction);

		// Create UsernamePassword
		// To Base64 decoding, Apache common-codec is used.
		String authString = pUsername + ":" + pPassword;
		byte[] authEncBytes = Base64.encodeBase64(authString.getBytes());
		String authStringEnc = new String(authEncBytes);
		httpConn.setRequestProperty("Authorization", "Basic " + authStringEnc);

		// httpConn.setRequestProperty("Authorization","Basic Z295YWxyYWRtaW46VHJhbnNmZXIxMiM=");
		httpConn.setRequestMethod("POST");
		httpConn.setDoOutput(true);
		httpConn.setDoInput(true);

		// Everything's set up; send the XML that was read in to b.
		OutputStream out = httpConn.getOutputStream();
		out.write(b);
		out.close();

		// Read the response and write it to standard out.
		InputStreamReader isr = new InputStreamReader(httpConn.getInputStream());
		BufferedReader in = new BufferedReader(isr);

		String inputLine;
		String output = "";
		while ((inputLine = in.readLine()) != null) {
			output = output + inputLine;
		}

		in.close();
		return output;
	}

	public <AbstractProject> boolean isApplicable(
			Class<? extends AbstractProject> aClass) {
		// Indicates that this builder can be used with all kinds of project
		// types
		return true;
	}

	public static void copy(InputStream in, OutputStream out)
			throws IOException {

		// do not allow other threads to read from the input or write to the
		// output while copying is taking place
		synchronized (in) {
			synchronized (out) {

				byte[] buffer = new byte[256];
				while (true) {
					int bytesRead = in.read(buffer);
					if (bytesRead == -1)
						break;
					out.write(buffer, 0, bytesRead);
				}
			}
		}
	}

	@Override
	public boolean perform(AbstractBuild build, Launcher launcher,
			BuildListener listener) {
		this.build=build;
		logStream = listener.getLogger();
		javaPostToDatapower connections = new javaPostToDatapower();
		
		debug("in perform");
		
		String dir = null;

		try {
			dir = build.getWorkspace().toURI().getPath();
			logStream.println("[INFO] *************************************************************************************************************");

			logStream.println("[INFO] Searching for DATAPOWER directories - "
							+ dir);
			logStream.println("[INFO] *************************************************************************************************************");


		} catch (Exception e) {
			// TODO Auto-generated catch block
			logStream.println("[INFO] ");
			e.printStackTrace(logStream);
		}
		debug("dir " + dir);
		File fDir = new File(dir);
		File[] files = fDir.listFiles();
		for (int i = 0; i < files.length; i++) {
			if (files[i].isDirectory()) {
				if (files[i].getName().endsWith("_dp"))
					doIt(files[i], connections);
			}
		}

		return true;
	}

	@Extension
	// This indicates to Jenkins that this is an implementation of an extension
	// point.
	public static final class DescriptorImpl extends
			BuildStepDescriptor<Builder> {
		/**
		 * To persist global configuration information, simply store it in a
		 * field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */
		private static String url;
		private static String device;
		private static String user;
		private static String password;

		/**
		 * In order to load the persisted global configuration, you have to call
		 * load() in the constructor.
		 */
		public DescriptorImpl() {
			load();
		}

		/**
		 * Performs on-the-fly validation of the form field 'name'.
		 *
		 * @param value
		 *            This parameter receives the value that the user has typed.
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 *         <p>
		 *         Note that returning {@link FormValidation#error(String)} does
		 *         not prevent the form from being saved. It just means that a
		 *         message will be displayed to the user.
		 */
		public FormValidation doCheckName(@QueryParameter String value)
				throws IOException, ServletException {
			if (value.length() == 0)
				return FormValidation.error("Please set a name");
			if (value.length() < 4)
				return FormValidation.warning("Isn't the name too short?");
			return FormValidation.ok();
		}

		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			// Indicates that this builder can be used with all kinds of project
			// types
			return true;
		}

		/**
		 * This human readable name is used in the configuration screen.
		 */
		public String getDisplayName() {
			return "Deploy_DP";
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject formData)
				throws FormException {
			dumpProps();
			url = formData.getString("url");
			device = formData.getString("device");
			user = formData.getString("user");
			password = formData.getString("password");
			save();
			return super.configure(req, formData);
		}

		private static void dumpProps() {
			dp_soma.debug("start");
			List<TopLevelItem> aa = Hudson.getInstance().getItems();

			for (TopLevelItem item : aa) {
				Collection<? extends Job> jobs = item.getAllJobs();
				for (Job job : jobs) {
					List props = job.getAllProperties();
					for (Object p : props) {
						dp_soma.debug((String) p);
					}
				}
			}
		}

		/**
		 * This method returns true if the global configuration says we should
		 * speak French.
		 *
		 * The method name is bit awkward because global.jelly calls this method
		 * to determine the initial state of the checkbox by the naming
		 * convention.
		 */
		
		public static String getUrl() {
			return url;
		}

		public void setUrl(String url) {
			DescriptorImpl.url = url;
		}

		public static String getDevice() {
			return device;
		}

		public void setDevice(String device) {
			DescriptorImpl.device = device;
		}

		public static String getUser() {
			return user;
		}

		public void setUser(String user) {
			DescriptorImpl.user = user;
		}

		public static String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			DescriptorImpl.password = password;
		}

	}

	public static void debug(String s) {
		try {
			PrintWriter pw = new PrintWriter(
					new FileWriter("c:/logs.txt", true));

			pw.println(s);
			pw.flush();
			pw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			logStream.println("[INFO] ");
			e.printStackTrace(logStream);
		}
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}
}
