from burp import IBurpExtender, IScanIssue, IScannerCheck, IContextMenuFactory, IContextMenuInvocation, ITab
from javax.swing import JMenuItem
from javax import swing
from javax.swing import JPanel, JButton, JList, JTable, table, JLabel, JScrollPane, JTextField, WindowConstants, GroupLayout, LayoutStyle, JFrame
from java.awt import BorderLayout
import java.util.ArrayList as ArrayList
import java.lang.String as String
from java.lang import Short

import thread
import hashlib

queryPayloadsFile = open('query payloads.txt', "r")
queryPayloadsFromFile = queryPayloadsFile.readlines()

headerPayloadsFile = open('header payloads.txt', "r")
headerPayloadsFromFile = headerPayloadsFile.readlines()

extentionName = "403 Bypasser"
requestNum = 2

class uiTab(JFrame):

	def queryAddButtonClicked(self, event):
		textFieldValue = self.queryPayloadsAddPayloadTextField.getText()

		if textFieldValue != "":
			tableModel = self.queryPayloadsTable.getModel()
			tableModel.addRow([textFieldValue])
		self.queryPayloadsAddPayloadTextField.setText("")

	def queryClearButtonClicked(self, event):
		global requestNum
		requestNum = 2
		tableModel = self.queryPayloadsTable.getModel()
		tableModel.setRowCount(0)

	def queryRemoveButtonClicked(self, event):
		tableModel = self.queryPayloadsTable.getModel()
		selectedRows = self.queryPayloadsTable.getSelectedRows()
		for row in selectedRows:
			tableModel.removeRow(row)
		global requestNum
		if requestNum > 2:
			requestNum -= 1

	def headerAddButtonClicked(self, event):
		textFieldValue = self.headerPayloadsAddPayloadTextField.getText()

		if textFieldValue != "":
			tableModel = self.headerPayloadsTable.getModel()
			tableModel.addRow([textFieldValue])
		self.headerPayloadsAddPayloadTextField.setText("")

	def headerClearButtonClicked(self, event):
		global requestNum
		requestNum = 2
		tableModel = self.headerPayloadsTable.getModel()
		tableModel.setRowCount(0)

	def headerRemoveButtonClicked(self, event):
		tableModel = self.headerPayloadsTable.getModel()
		selectedRows = self.headerPayloadsTable.getSelectedRows()
		for row in selectedRows:
			tableModel.removeRow(row)
		global requestNum
		if requestNum > 2:
			requestNum -= 1

	def __init__(self):
		self.queryPayloadsLabel = JLabel()
		self.jScrollPane1 = JScrollPane()
		self.queryPayloadsTable = JTable()
		self.queryPayloadsAddPayloadTextField = JTextField()
		self.queryPayloadsAddButton = JButton("Add", actionPerformed=self.queryAddButtonClicked)
		self.queryPayloadsClearButton = JButton("Clear", actionPerformed=self.queryClearButtonClicked)
		self.queryPayloadsRemoveButton = JButton("Remove", actionPerformed=self.queryRemoveButtonClicked)

		self.headerPayloadsLabel = JLabel()
		self.jScrollPane2 = JScrollPane()
		self.headerPayloadsTable = JTable()
		self.headerPayloadsAddPayloadTextField = JTextField()
		self.headerPayloadsAddButton = JButton("Add", actionPerformed=self.headerAddButtonClicked)
		self.headerPayloadsClearButton = JButton("Clear", actionPerformed=self.headerClearButtonClicked)
		self.headerPayloadsRemoveButton = JButton("Remove", actionPerformed=self.headerRemoveButtonClicked)

		self.panel = JPanel()

		self.queryPayloadsLabel.setText("Query Payloads")

		queryTableData = []
		for queryPayload in queryPayloadsFromFile:
			queryTableData.append([queryPayload])

		headerTableData = []
		for headerPayload in headerPayloadsFromFile:
			headerTableData.append([headerPayload])

		queryTableColumns = [None]
		queryTableModel = table.DefaultTableModel(queryTableData,queryTableColumns)
		self.queryPayloadsTable.setModel(queryTableModel)
		self.queryPayloadsTable.getTableHeader().setUI(None)

		self.jScrollPane1.setViewportView(self.queryPayloadsTable)

		self.jScrollPane1.setViewportView(self.queryPayloadsTable)

		self.headerPayloadsLabel.setText("Header Payloads")

		headerTableColumns = [None]
		headerTableModel = table.DefaultTableModel(headerTableData,headerTableColumns)
		self.headerPayloadsTable.setModel(headerTableModel)
		self.headerPayloadsTable.getTableHeader().setUI(None)
		self.jScrollPane2.setViewportView(self.headerPayloadsTable)



		layout = GroupLayout(self.panel)
		self.panel.setLayout(layout)

		
		layout.setHorizontalGroup(
			layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
					.addComponent(self.queryPayloadsAddButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(self.queryPayloadsRemoveButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(self.queryPayloadsClearButton, GroupLayout.PREFERRED_SIZE, 93, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
					.addComponent(self.queryPayloadsLabel)
					.addComponent(self.queryPayloadsAddPayloadTextField)
					.addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 107, GroupLayout.PREFERRED_SIZE))
				.addGap(100, 100, 100)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
					.addComponent(self.headerPayloadsAddButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(self.headerPayloadsRemoveButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(self.headerPayloadsClearButton, GroupLayout.PREFERRED_SIZE, 93, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
					.addComponent(self.headerPayloadsLabel)
					.addComponent(self.headerPayloadsAddPayloadTextField)
					.addComponent(self.jScrollPane2, GroupLayout.PREFERRED_SIZE, 107, GroupLayout.PREFERRED_SIZE))
				.addGap(0, 483, Short.MAX_VALUE))
		)
		layout.setVerticalGroup(
			layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup()
				.addGap(17, 17, 17)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
					.addGroup(layout.createSequentialGroup()
						.addComponent(self.headerPayloadsLabel)
						.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
							.addComponent(self.jScrollPane2, GroupLayout.PREFERRED_SIZE, 195, GroupLayout.PREFERRED_SIZE)
							.addGroup(layout.createSequentialGroup()
								.addComponent(self.headerPayloadsClearButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(self.headerPayloadsRemoveButton)))
						.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
							.addComponent(self.headerPayloadsAddPayloadTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addComponent(self.headerPayloadsAddButton)))
					.addGroup(layout.createSequentialGroup()
						.addComponent(self.queryPayloadsLabel)
						.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
							.addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 195, GroupLayout.PREFERRED_SIZE)
							.addGroup(layout.createSequentialGroup()
								.addComponent(self.queryPayloadsClearButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(self.queryPayloadsRemoveButton)))
						.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
							.addComponent(self.queryPayloadsAddPayloadTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addComponent(self.queryPayloadsAddButton))))
				.addContainerGap(324, Short.MAX_VALUE))
		)


class Result:
	def __init__(self, url, data, httpRequestResponse, helpers):
		self.url = url
		self.data = data
		self.httpRequestResponse = httpRequestResponse

		response = httpRequestResponse.getResponse()
		self.analyseResp(response, helpers)
		# self.statuscode = statuscode
		# self.responsesize = responsesize
		# self.contenthash = contenthash

	def analyseResp(self, response, helpers):
		respInfo = helpers.analyzeResponse(response)
		self.statuscode = respInfo.getStatusCode()
		respString = helpers.bytesToString(response)
		respBody = respString[respInfo.getBodyOffset():]
		self.responsesize = len(respBody)

		respHeaders = respInfo.getHeaders()
		for hdr in respHeaders:
			hdr = str(hdr)
			if hdr.startswith("Content-Length:"):
				responsesizeFromHeader = int(hdr[16:])
				if self.responsesize != responsesizeFromHeader:
					print('Conflicting response size encountered!')
					print('From raw analysis: {}'.format(self.responsesize))
					print('From Content-Length header: {}'.format(responsesizeFromHeader))
		
		# use a deterministic hash function
		self.contenthash = hashlib.md5(respBody).hexdigest()


	def renderRow(self, reqNum):
		cols = [
			str(reqNum),
			self.url,
			self.data,
			str(self.statuscode),
			str(self.responsesize),
		]
		return "<tr>" + "".join("<td>" + col + "</td>" for col in cols) + "</tr>"
	
	@staticmethod
	def deduplicateResults(resultsList):
		seen = set()
		deduped = []
		for res in resultsList:
			if res.contenthash in seen:
				continue
			seen.add(res.contenthash)
			deduped.append(res)
		return deduped
	
	@staticmethod
	def renderResultsToTable(resultsList, startReqNum=2, dataHeader=""):
		headers = [
			"Request #",
			"URL",
			dataHeader,
			"Status Code",
			"Response Size"
		]
		headerrow = "<tr>" + "".join("<td>" + col + "</td>" for col in headers) + "</tr>"
		data = "".join(res.renderRow(reqNum) for reqNum, res in enumerate(resultsList, startReqNum))
		return "<table>" + headerrow + data + "</table>"
		

class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory, ITab):
	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = self.callbacks.getHelpers()
		self.callbacks.registerScannerCheck(self)
		self.callbacks.registerContextMenuFactory(self)
		self.callbacks.setExtensionName(extentionName)

		self.callbacks.addSuiteTab(self)

		sys.stdout = self.callbacks.getStdout()
		sys.stderr = self.callbacks.getStderr()
		
		return None

	def getTabCaption(self):
		return extentionName

	def getUiComponent(self):
		self.frm = uiTab()

		return self.frm.panel

	def createMenuItems(self, invocation):
		self.context = invocation
		self.menuList = []
		self.menuItem = JMenuItem("Bypass 403", actionPerformed=self.testFromMenu)
		self.menuList.append(self.menuItem)
		return self.menuList

	def testFromMenu(self, event):
		selectedMessages = self.context.getSelectedMessages()
		for message in selectedMessages:
			thread.start_new_thread(self.doActiveScan, (message, "" , True, ))

		return None


	def isPositive(self, responseInfo):
		responseCode = responseInfo.getStatusCode()
		return responseCode < 400

	def isInteresting(self, responseInfo):
		responseCode = responseInfo.getStatusCode()
		# TODO: extend scope of interesting responses
		return responseCode == 403

	def findAllCharIndexesInString(self,s, ch):
		return [i for i, ltr in enumerate(s) if ltr == ch]

	def generatePayloads(self, path, payload):
		payloads = []

		#generate payloads before slash
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + payload + path[i:]
			payloads.append(pathWithPayload)

		#generate payloads after slash
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/" + payload + path[i+1:]
			payloads.append(pathWithPayload)

		#generate payloads in between slashes
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/" + payload + "/" + path[i+1:]
			payloads.append(pathWithPayload)

		#generate payloads at the end of the path
		payloads.append(path + "/" + payload)
		payloads.append(path + "/" + payload + "/")

		return payloads
	
	@staticmethod
	def addOrReplaceHeader(headers, newHeader):
		"""Returns a new ArrayList of headers containing the new header."""
		hdrsArrayList = ArrayList()
		hdrName = newHeader.split(" ")[0].lower()
		hdrAdded = False
		for header in headers:
			if header.lower().startswith(hdrName):
				hdrsArrayList.add(String(newHeader))
				hdrAdded = True
			else:
				hdrsArrayList.add(String(header))

		if hdrAdded == False:
			hdrsArrayList.add(String(newHeader))

		return hdrsArrayList


	def tryBypassWithQueryPayload(self, request, payload, httpService):
		results = []

		requestPath = request.getUrl().getPath()
		payloads = self.generatePayloads(requestPath, payload)

		requestInfo = self.helpers.analyzeRequest(request)
		headers = requestInfo.getHeaders()
		firstline = headers[0]

		originalRequest = self.helpers.bytesToString(request.getRequest())
		for pathToTest in payloads:
			headers[0] = firstline.replace(requestPath, pathToTest, 1)
			requestBody = originalRequest[requestInfo.getBodyOffset():]

			newRequest = self.helpers.buildHttpMessage(headers, requestBody)
			try:
				# TODO: add try-except to other makeHttpRequest calls
				newRequestResponse = self.callbacks.makeHttpRequest(httpService, newRequest)
			except:
				print("No response from server: {}".format(headers[0]))
				continue

			if self.isPositive(self.helpers.analyzeResponse(newRequestResponse.getResponse())):
				results.append(Result(
					url=pathToTest.replace(payload, "<b>" + payload + "</b>"),
					data="",
					httpRequestResponse=newRequestResponse,
					helpers=self.helpers,
				))

		return results
	

	def tryBypassWithHeaderPayload(self, baseRequestResponse, payload, httpService):
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		headers = requestInfo.getHeaders()
		headers = self.addOrReplaceHeader(headers, payload)

		requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]

		newRequest = self.helpers.buildHttpMessage(headers, requestBody)
		newRequestResponse = self.callbacks.makeHttpRequest(httpService, newRequest)

		if self.isPositive(self.helpers.analyzeResponse(newRequestResponse.getResponse())):
			return [
				Result(
					url=str(baseRequestResponse.getUrl().getPath()),
					data=payload.split(":")[0], # Display specific header name.
					httpRequestResponse=newRequestResponse,
					helpers=self.helpers,
				)
			]

		return []


	def tryBypassWithMethod(self, baseRequestResponse, method, httpService):
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		headers = requestInfo.getHeaders()
		headers[0] = method + " " + " ".join(headers[0].split(" ")[1:])

		if method.upper() == 'POST':
			headers = self.addOrReplaceHeader(headers, "Content-Length: 0")

		requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]
		newRequest = self.helpers.buildHttpMessage(headers, requestBody)
		newRequestResponse = self.callbacks.makeHttpRequest(httpService, newRequest)

		if self.isPositive(self.helpers.analyzeResponse(newRequestResponse.getResponse())):
			return [
				Result(
					url=str(baseRequestResponse.getUrl().getPath()),
					data=method,
					httpRequestResponse=newRequestResponse,
					helpers=self.helpers,
				)
			]

		return []


	def tryBypassWithUserAgent(self, baseRequestResponse, agent, httpService):
		headerAlreadyAdded = False
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		headers = requestInfo.getHeaders()
		headers = self.addOrReplaceHeader(headers, 'User-Agent: {}'.format(agent))

		requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]
		newRequest = self.helpers.buildHttpMessage(headers, requestBody)
		newRequestResponse = self.callbacks.makeHttpRequest(httpService, newRequest)

		if self.isPositive(self.helpers.analyzeResponse(newRequestResponse.getResponse())):
			return [
				Result(
					url=str(baseRequestResponse.getUrl().getPath()),
					data=agent if len(agent) < 40 else agent[:15] + "..." + agent[-15:],
					httpRequestResponse=newRequestResponse,
					helpers=self.helpers,
				)
			]

		return []
		
	
	def tryBypassWithDowngradedHttpAndNoHeaders(self, baseRequestResponse, httpService):
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		headers = requestInfo.getHeaders()
		newHeader = headers[0].replace("HTTP/1.1", "HTTP/1.0")

		requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]
		headers = ArrayList()
		headers.add(String(newHeader))

		newRequest = self.helpers.buildHttpMessage(headers, requestBody)
		newRequestResponse = self.callbacks.makeHttpRequest(httpService, newRequest)

		if self.isPositive(self.helpers.analyzeResponse(newRequestResponse.getResponse())):
			return [
				Result(
					url=str(baseRequestResponse.getUrl().getPath()),
					data="",
					httpRequestResponse=newRequestResponse,
					helpers=self.helpers,
				)
			]

		return []


	def makeScanIssueFromResults(self, baseRequestResponse, results, title, severity, dataHeader="Data", dedup=True):
		if len(results) == 0:
			return []
	
		if dedup:
			results = Result.deduplicateResults(results)

		issueHttpMessages = [baseRequestResponse] + [res.httpRequestResponse for res in results]
		issueDetails = Result.renderResultsToTable(results, 2, dataHeader=dataHeader)

		return [
			CustomScanIssue(
				baseRequestResponse.getHttpService(),
				self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
				issueHttpMessages,
				title,
				issueDetails,
				severity,
			)
		]


	def testQueryBasedIssues(self, baseRequestResponse):
		results = []

		queryPayloadsFromTable = []
		for rowIndex in range(self.frm.queryPayloadsTable.getRowCount()):
			queryPayloadsFromTable.append(str(self.frm.queryPayloadsTable.getValueAt(rowIndex, 0)))

		for payload in queryPayloadsFromTable:
			payload = payload.rstrip('\n')
			result = self.tryBypassWithQueryPayload(baseRequestResponse, payload, baseRequestResponse.getHttpService())
			results += result

		return self.makeScanIssueFromResults(
				baseRequestResponse,
				results,
				title="Possible 403 Bypass - Query Based",
				severity="High",
				dataHeader="",
			)
	
	def testHeaderBasedPayloads(self, baseRequestResponse):
		results = []

		headerPayloadsFromTable = []
		for rowIndex in range(self.frm.headerPayloadsTable.getRowCount()):
			headerPayloadsFromTable.append(str(self.frm.headerPayloadsTable.getValueAt(rowIndex, 0)))

		# add request-dependent payloads, e.g. Referer: http://{host}:{port}/
		url = self.helpers.analyzeRequest(baseRequestResponse).getUrl()
		scheme, port, host = url.getProtocol(), url.getPort(), url.getHost()
		if (scheme == 'https' and port == 443) or (scheme == 'http' and port == 80):
			refurl = '{}://{}/'.format(scheme, host)
		else:
			refurl = '{}://{}:{}/'.format(scheme, host, port)
		headerPayloadsFromTable.append('Referer: {}'.format(refurl))

		for payload in headerPayloadsFromTable:
			payload = payload.rstrip('\n')
			result = self.tryBypassWithHeaderPayload(baseRequestResponse, payload, baseRequestResponse.getHttpService())
			results += result

		return self.makeScanIssueFromResults(
				baseRequestResponse,
				results,
				title="Possible 403 Bypass - Header Based",
				severity="High",
				dataHeader="Header",
			)

	def testMethodBasedIssues(self, baseRequestResponse):
		results = []
		methods = [
			'GET', 'POST', 'OPTIONS', 'TRACE', 'DEBUG', 'HEAD', 'CONNECT',
			'ASDF' # Try nonsense method.
		]
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		requestHeaders = requestInfo.getHeaders()
		for method in methods:
			if requestHeaders[0].startswith(method):
				continue
			result = self.tryBypassWithMethod(baseRequestResponse, method, baseRequestResponse.getHttpService())
			results += result

		return self.makeScanIssueFromResults(
				baseRequestResponse,
				results,
				title="Possible 403 Bypass - Method Based",
				severity="High",
				dataHeader="Method",
				dedup=False,
			)
	
	def testAgentBasedIssues(self, baseRequestResponse):
		results = []
		agents = [
			# Desktop
			# Chrome, Windows
			'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/602.2.4 (KHTML, like Gecko) Chrome/95.5.4935.611 Safari/602.2.4',
			# Chrome, macOS
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4758.102 Safari/537.36',
			# Firefox, Linux
			'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:19.0) Gecko/20100101 Firefox/19.0',

			# Mobile
			# Safari, iOS
			'Mozilla/5.0 (iPhone; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/609.0.8 (KHTML, like Gecko) Mobile/14A25 Safari/609.0.8',
			# Chrome, Android, Samsung
			'Mozilla/5.0 (Linux; U; Android-4.0.3; en-us; Galaxy Nexus Build/IML74K) AppleWebKit/535.7 (KHTML, like Gecko) CrMo/16.0.912.75 Mobile Safari/535.7',
			# Firefox, Android, Lenovo
			'Mozilla/5.0 (Android 11; Mobile; Lenovo YT-X705X; rv:129.0) Gecko/129.0 Firefox/129.0',
			
			# Uncommon
			'Mozilla/5.0 (Linux; U; Android 9.1; Z062D) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/14.0.5611.349 Mobile Safari/537.36 OPR/13.10.3262.690',
			'Mozilla/5.0 (Linux; U; Android 4.0.0; en-us; KFMAWI Build/KM21) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.49 like Chrome/126.9.768.105 Safari/537.36',
			'Mozilla/5.0 (Linux; Android 9; JDN2-AL50 Build/HUAWEIJDN2-AL50; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/76.0.3809.89 Mobile Safari/537.36 T7/12.13.0 SP-engine/2.29.0 matrixstyle/0 lite baiduboxapp/5.8.0.10 (Baidu; P1 9) NABar/1.',
		]
		for agent in agents:
			result = self.tryBypassWithUserAgent(baseRequestResponse, agent, baseRequestResponse.getHttpService())
			results += result

		return self.makeScanIssueFromResults(
				baseRequestResponse,
				results,
				title="Possible 403 Bypass - Agent Based",
				severity="High",
				dataHeader="Agent",
				dedup=True,
			)
	
	def testDowngradeIssues(self, baseRequestResponse):
		# change the protocol to HTTP/1.0 and remove all other headers
		downgradedHttpResults = self.tryBypassWithDowngradedHttpAndNoHeaders(baseRequestResponse, baseRequestResponse.getHttpService())
		return self.makeScanIssueFromResults(
				baseRequestResponse,
				downgradedHttpResults,
				title="Possible 403 Bypass - Downgraded HTTP Version",
				severity="High",
				dataHeader="",
				dedup=False,
			)

	def doPassiveScan(self, baseRequestResponse):
		return None

	def doActiveScan(self, baseRequestResponse, insertionPoint, isCalledFromMenu=False):
		response = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
		if self.isInteresting(response) == False and isCalledFromMenu == False:
			return None

		issues = self.testRequest(baseRequestResponse)
		if len(issues) == 0:
			return None
		
		if isCalledFromMenu == False:
			return issues
		
		for issue in issues:
			self.callbacks.addScanIssue(issue)

	def testRequest(self, baseRequestResponse):
		findings = []
		findings += self.testHeaderBasedPayloads(baseRequestResponse)
		findings += self.testMethodBasedIssues(baseRequestResponse)
		findings += self.testAgentBasedIssues(baseRequestResponse)
		findings += self.testDowngradeIssues(baseRequestResponse)
		findings += self.testQueryBasedIssues(baseRequestResponse)
		return findings

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
			return -1
		else:
			return 0

class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Tentative"

	def getIssueBackground(self):
		return extentionName + " sent a request and got 403 response. " + extentionName + " sent another request and got 2XX-3XX response, this may indicate a misconfiguration on the server side that allows access to forbidden pages."

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail
	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
