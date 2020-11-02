/*
 * Bu dosyada yer alan kaynak kodlarýnýn, Fikir ve Sanat Eserleri Kanunu ve diðer ilgili mevzuattan doðan tüm fikri, 
 * sýnai ve ticari haklarý tescil edilmesi koþuluna baðlý olmaksýzýn TÜBÝTAK'a aittir. Bu haklarýn ihlal edilmesi 
 * halinde, ihlalden kaynaklanan her türlü idari, hukuki, cezai ve mali sorumluluk ihlal eden tarafa ait olup, 
 * TÜBÝTAK'ýn ihlalden kaynaklý hukuksal bir yaptýrýmla karþý karþýya kalmasý durumunda tüm yasal haklarý saklýdýr.
 */
package tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.servlet.ServletContext;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import tr.gov.tubitak.uekae.g222.sydgm.accounting.foundation.accountingparameter.AccountingParameterManagerRemote;
import tr.gov.tubitak.uekae.g222.sydgm.accounting.sygm.accountingcodelabel.SYGMAccCodeLabelManagerRemote;
import tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.common.DateUtil;
import tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.persistence.PersistenceManagerRemote;
import tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.persistence.QueryingEntityManagerRemote;
import tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.persistence.Toucher;
import tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.rule.RuleUtils;
import tr.gov.tubitak.uekae.g222.sydgm.common.infrastructure.service.businessrule.PersistUsageLogRule;
import tr.gov.tubitak.uekae.g222.sydgm.common.logging.LogOperationsRemote;
import tr.gov.tubitak.uekae.g222.sydgm.common.parameter.ParameterManagerRemote;
import tr.gov.tubitak.uekae.g222.sydgm.common.query.RetrieveEntityByInProperty;
import tr.gov.tubitak.uekae.g222.sydgm.entities.Foundation;
import tr.gov.tubitak.uekae.g222.sydgm.entities.RAccessRight;
import tr.gov.tubitak.uekae.g222.sydgm.entities.User;
import tr.gov.tubitak.uekae.g222.sydgm.entities.dto.ApplicationStartUpInformation;
import tr.gov.tubitak.uekae.g222.sydgm.entities.dto.ServerMonitoringDTO;
import tr.gov.tubitak.uekae.g222.sydgm.entities.dto.UserSessionDTO;
import tr.gov.tubitak.uekae.g222.sydgm.foundationoperation.user.UserManagerRemote;
import tr.gov.tubitak.uekae.g222.sydgm.foundationoperation.user.UserSessionMonitoringRemote;
import tr.gov.tubitak.uekae.g222.sydgm.foundationoperation.user.query.RetrieveActiveUserByUserNameCQC;
import tr.gov.tubitak.uekae.g222.sydgm.util.ReflectionUtils;
import weblogic.javaee.CallByReference;

import com.sun.org.apache.xerces.internal.parsers.DOMParser;

/**
 * Session Bean implementation class LoginManager
 */
@CallByReference
@Stateless (mappedName = "LoginManager")
public class LoginManager implements LoginManagerRemote {

	@EJB
	PersistenceManagerRemote persistenceManager;

	@EJB
	private UserManagerRemote userManager;

	@EJB
	private ParameterManagerRemote parameterManager;

	@EJB
	private UserSessionMonitoringRemote userSessionMonitoring;

	@EJB
	private AccountingParameterManagerRemote accParameterManager;
	
	@EJB
	private SYGMAccCodeLabelManagerRemote sygmAccLabelManager;

	private SessionAccessor sessionAccessor = new FlexContextSessionAccessor();

	@EJB
	QueryingEntityManagerRemote queryManager;

	@EJB
	private LogOperationsRemote logOperations;

	@Resource
	private SessionContext sessionContext;

	/**
	 * Default constructor.
	 */
	public LoginManager() { }

	@Override
	// @RolesAllowed({ "RHaneDosyasiOku","RSHaneDosyasiIslemleriOku" })
	public ApplicationStartUpInformation getApplicationStartUpInformation() {
		ApplicationStartUpInformation applicationStartUpInformation = new ApplicationStartUpInformation();
		applicationStartUpInformation.setDeployNumber(getDeployNumber());
		applicationStartUpInformation.setServerName(getServerName());

		User user = initialize();
		applicationStartUpInformation.setUser(user);
		if (user != null) {
			List<RAccessRight> accessRigthList = userManager.getAccessRightsByUsernameAndUserType(user.getUsername());
			applicationStartUpInformation.setAccessRightList(accessRigthList);
			applicationStartUpInformation.setServerDate(getServerDate());
			applicationStartUpInformation.setServerFullURL(getServerFullURL());
		}

		return applicationStartUpInformation;
	}
	
	private User initialize() {

		String userName = sessionAccessor.getHttpRequest().getRemoteUser();
		User user = (User) sessionAccessor.getAttribute("user");
		if (user == null) {
			if (userName != null && !"".equals(userName)) {
				user = validateUser(userName);
				if (user != null) {
					parameterManager.setSystemParameters();
					user.setUuid(UUID.randomUUID().toString());
					sessionAccessor.setAttribute("user", user);

					accParameterManager.setAccCodeLabelAccessorMap();
					sygmAccLabelManager.setAccCodeLabelAccessorMap();
				} else {
					throw new RuntimeException("User NULL !");
				}
			}

		} else {
			if (!userName.equals(user.getUsername())) {
				logOut();
				user = null;
			}
		}
		return user;
	}
	

	@Override
	public void logOut() {
		sessionAccessor.getHttpRequest().getSession().invalidate();
		sessionAccessor.invalidate();
	}

	@Override
	// @RolesAllowed({ "RHaneDosyasiOku","RSHaneDosyasiIslemleriOku" })
	public User getAuthenticatedUser() {
		User user = (User) sessionAccessor.getAttribute("user");
		if (user == null) {
			user = getUserBySessionContext();
		}
		return user;
	}

	@Override
	// @RolesAllowed({ "RHaneDosyasiOku","RSHaneDosyasiIslemleriOku" })
	public User getAttachedAuthenticatedUser() {
		User user = getAuthenticatedUser();
		return persistenceManager.find(User.class, user.getId());
	}

	/**
	 * When ThreadLocal variable of the session is null, user is handled over caller principal
	 * @return User
	 */

	public User getUserBySessionContext() {
		User user = null;
		if (sessionContext != null && sessionContext.getCallerPrincipal() != null) {
			Principal callerPrincipal = sessionContext.getCallerPrincipal();
			String userName = callerPrincipal.toString();
			if (userName != null && !userName.isEmpty() && !userName.toLowerCase().contains("anonymous")) {
				user = validateUser(userName);
			}
		}
		return user;
	}

	@Override
	public Date getServerDate() {
		return DateUtil.getCurrentDate();
	}

	@Override
	public String getClientIPAddress() {
		if (sessionAccessor.getHttpRequest() == null) {
			return null;
		}
		return sessionAccessor.getHttpRequest().getRemoteAddr();
	}

	@Override
	public String getServerFullURL() {
		String servletContextName = sessionAccessor.getServletContext().getServletContextName();

		String requestURI = sessionAccessor.getHttpRequest().getRequestURI();
		String requestURL = sessionAccessor.getHttpRequest().getRequestURL().toString();

		int endOfServerNameIndex = requestURL.indexOf(requestURI);

		String serverFullName = requestURL.substring(0, endOfServerNameIndex);
		serverFullName += "/" + servletContextName;

		return serverFullName;
	}

	@Override
	public String getDeployNumber() {
		ServletContext context = sessionAccessor.getServletContext();

		String deployNumber = (String) context.getAttribute("deploynumber");
		if (deployNumber == null || deployNumber.equals("")) {
			setApplicationScopeParameters();
			deployNumber = (String) context.getAttribute("deploynumber");
		}
		return deployNumber;
	}

	@Override
	public ServerMonitoringDTO getOnlineUsersList() {
		 ServerMonitoringDTO userSessionListInAllServer = userSessionMonitoring.getUserSessionListInAllServer();
		 List<UserSessionDTO> sessionList = userSessionListInAllServer.getSessionList();
		 List<Long> extractedUserIdList = ReflectionUtils.getInstance().extractUniquePropertyList(sessionList, new String[]{"userId"}, Long.class);
		 setUserSessionsByDBQueryResults(sessionList, extractedUserIdList);
		 return userSessionListInAllServer;
	}

	private void setUserSessionsByDBQueryResults(List<UserSessionDTO> sessionList, List<Long> extractedUserIdList) {
		if(!extractedUserIdList.isEmpty()){
			 RetrieveEntityByInProperty retrieveEntityByInIdCQC = new RetrieveEntityByInProperty(User.class,"id",extractedUserIdList);
			 List<User> userListFromDB = queryManager.getResultList(retrieveEntityByInIdCQC, User.class);
			 setUserSessionDTOList(sessionList,userListFromDB);
		 }
	}

	private void setUserSessionDTOList(List<UserSessionDTO> sessionList, List<User> userListFromDB) {
		for (User userFromDB : userListFromDB) {
			for (UserSessionDTO userDTO : sessionList) {
				if(userFromDB.getId().equals(userDTO.getUserId())){
					userDTO.setUsername(userFromDB.getUsername());
					userDTO.setNameSurname(userFromDB.getNameSurname());
					userDTO.setFoundationName(userFromDB.getFoundation() == null ? " " : userFromDB.getFoundation().getFoundationName());
					userDTO.setCityName(userFromDB.getFoundation().getDistrict() == null ? " " : userFromDB.getFoundation().getDistrict().getCity().getCityName());
				}
			}
		}
	}

	private void setApplicationScopeParameters() {
		String fileName = "/WEB-INF/config.properties";
		ServletContext context = sessionAccessor.getServletContext();
		InputStream is = context.getResourceAsStream(fileName);

		if (is != null) {
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader reader = new BufferedReader(isr);
			String str = "";
			try {
				while ((str = reader.readLine()) != null) {

					String[] strArray = str.split("\r\n");
					for (String s : strArray) {
						int equalIndex = s.indexOf("=");
						String keyString = s.substring(0, equalIndex);
						String valString = s.substring(equalIndex + 1);
						if (keyString.equals("version")) {
							context.setAttribute("version", valString);
							context.setAttribute("deploynumber", valString);
						}
					}
				}

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	// @RolesAllowed({ "RHaneDosyasiOku","RSHaneDosyasiIslemleriOku" })
	public Foundation getLoginFoundation() {
		return getAttachedAuthenticatedUser().getFoundation();
	}

	@Override
	public String getServerName() {
		ServletContext context = sessionAccessor.getServletContext();

		String serverName = (String) context.getAttribute("serverName");
		if (serverName == null || serverName.equals("")) {
			setServerNameApplicationScopeParameter();
			serverName = (String) context.getAttribute("serverName");
		}
		return serverName;
	}
	
	@Override
	public String getServerIP() {
		String hostAddress = "";
		try {
			hostAddress = InetAddress.getLocalHost().getHostAddress();
		} catch (UnknownHostException e) {
			e.printStackTrace();
			hostAddress = "BILINMIYOR";
		}
		return hostAddress;
	}

	@Override
	public void saveUsageLog(Object object) {

		List<Object[]> logList = (List) object;

		RuleUtils.executeRuleCollection(logOperations, PersistUsageLogRule.class, logList, getAuthenticatedUser().getId(), persistenceManager);
	}

	private void setServerNameApplicationScopeParameter() {
		String currentServerName = "";
		String serverDefinitionsFileName = "/WEB-INF/serverlist.xml";
		ServletContext context = sessionAccessor.getServletContext();
		InputStream in = context.getResourceAsStream(serverDefinitionsFileName);
		try {

			DOMParser parser = new DOMParser();
			parser.parse(new InputSource(in));

			Document doc = parser.getDocument();
			NodeList list = doc.getElementsByTagName("server");
			currentServerName = getCurrentServerName(list, InetAddress.getLocalHost().getHostAddress());
			if (currentServerName.equals("")) {
				currentServerName = getCurrentServerName(list, "localhost");
			}
			context.setAttribute("serverName", currentServerName);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String getCurrentServerName(NodeList list, String appServerAdress) {
		Node node = null;
		String currentServerName = "";
		for (int i = 0; i < list.getLength(); i++) {
			NamedNodeMap map = list.item(i).getAttributes();
			if (map.getNamedItem("hostname").getNodeValue().equals(appServerAdress)) {
				currentServerName = map.getNamedItem("serverLabelName").getNodeValue();
				node = list.item(i).getParentNode();
				currentServerName += "," + node.getAttributes().getNamedItem("serverLabelName").getNodeValue();
				return currentServerName;
			}
		}
		return currentServerName;
	}

	private User validateUser(String userName) {

		RetrieveActiveUserByUserNameCQC cqc = new RetrieveActiveUserByUserNameCQC(userName);
		User user = (User) queryManager.getSingleResult(cqc);

		if (user != null) {
			Toucher.touchFieldsOfObject(user, "foundation.district.city.region", "personnel");
		}

		return user;
	}
	
	/*
	 * Uzun süren istemci kaynaklý iþlemlerde session'ý açýk tutmak için kullanýlmaktadýr, silmeyiniz.
	 */
	@Override
	public void handleClientHeartBeat() 
	{
		/*
		 * Uzun süren istemci kaynaklı işlemlerde session'ı açık tutmak için kullanılmaktadır, silmeyiniz.
		 */
	}
}
