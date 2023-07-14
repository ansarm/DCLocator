//       dclocator.exe
//       By Ansar Mohammed
//       email:ansarm@gmail.com
//
//--------------------------------------------------------------
// for linux compile 
// install openldap-library
// compile with:  
// cc dclocator.c -lldap -lresolv -o dclocator

#if defined _WIN32
#include <windows.h>
#include <winldap.h>
#include <Windns.h>
#endif

#if defined __linux__ 
#include <ldap.h>
#include <resolv.h>
#endif

#include <stdio.h> 
#include <stdlib.h>

#define MaxString 4096
#define max(a,b)  (((a) > (b)) ? (a) : (b))

#define DS_PDC_FLAG 0x00000001 //The server holds the PDC FSMO role
#define DS_GC_FLAG 0x00000004  //The server is a GC server
#define DS_LDAP_FLAG 0x00000008 //The server is an LDAP server.
#define DS_DS_FLAG 0x00000010 //The server is a DC.
#define DS_KDC_FLAG 0x00000020 //The server is running the Kerberos Key Distribution Center service.
#define DS_TIMESERV_FLAG 0x00000040 //The Win32 Time Service, is present on the server.
#define DS_CLOSEST_FLAG 0x00000080  //The server is in the same site as the client.This is a hint to the client that it is well - connected to the server in terms of speed.
#define DS_WRITABLE_FLAG 0x00000100 //Indicates that the server is not an RODC
#define DS_GOOD_TIMESERV_FLAG 0x00000200 //The server is a reliable time server.
#define DS_NDNC_FLAG 0x00000400 //The NC is an application NC.
#define DS_SELECT_SECRET_DOMAIN_6_FLAG 0x00000800 //The server is an RODC.
#define DS_FULL_SECRET_DOMAIN_6_FLAG 0x00001000 //The server is a writable DC, not running Windows 2000 Server operating system or Windows Server 2003 operating system.
#define DS_WS_FLAG 0x00002000 //The Active Directory Web Service is present on the server.
#define DS_DS_8_FLAG 0x00004000 //The server is not running Windows 2000 operating system, Windows Server 2003, Windows Server 2008 operating system, or Windows Server 2008 R2 operating system.
#define DS_DS_9_FLAG 0x00008000 //The server is not running Windows 2000, Windows Server 2003, Windows Server 2008, Windows Server 2008 R2, or Windows Server 2012 operating system.
#define DS_DNS_CONTROLLER_FLAG 0x20000000 //The server has a DNS name.
#define DS_DNS_DOMAIN_FLAG 0x40000000 //The NC is a default NC.
#define DS_DNS_FOREST_FLAG 0x80000000 //The NC is the forest root.

int iVerbose = 0;

typedef struct ldap_ping_response
{
	unsigned short	opcode;
	unsigned short	Sbz;
	unsigned int	Flags;
	unsigned int	Data1;
	unsigned short	Data2;
	unsigned short	Data3;
	unsigned short	Data4;
	unsigned short	Data5;
	unsigned short	Data6;
	unsigned short	Data7;
	char			UTF8message[];
}
LDAP_PING_RESPONSE, *PLDAP_PING_RESPONSE;

typedef struct string_list
{
	char * szName;
	struct string_list * next;
}
STRING_LIST, *PSTRING_LIST;

int getlabelfromutf8(char * szLabel, char * buffer, int iBufferIndex)
{
	int iLabelIndex = 0;
	int iLabelLength = 0;
	int iCurrentLabelPosition = 0;
	memset(szLabel, 0, MaxString);

	while (iLabelIndex < MaxString)
	{
		if (buffer[iBufferIndex] == '\0')
		{
			szLabel[iLabelIndex] = buffer[iBufferIndex];
			iBufferIndex++;
			break;
		}
		if ((buffer[iBufferIndex] & 0xC0) == 0)
		{
			iLabelLength = iBufferIndex + buffer[iBufferIndex];
			while (iLabelLength > iBufferIndex)
			{
				iBufferIndex++;
				szLabel[iLabelIndex] = buffer[iBufferIndex];
				iLabelIndex++;
			}
			if (buffer[iBufferIndex + 1] != '\0')
				szLabel[iLabelIndex] = '.';
			iLabelIndex++;
			iBufferIndex++;
			iCurrentLabelPosition = max(iBufferIndex, iCurrentLabelPosition);
		}
		else
		{
			iBufferIndex++;
			iCurrentLabelPosition = max(iBufferIndex + 1, iCurrentLabelPosition);
			iBufferIndex = buffer[iBufferIndex] - 24;
		}
	}
	return max(iBufferIndex, iCurrentLabelPosition);
}

#if defined _WIN32
int get_hostnames_from_srv(char * szSrvRecord, PSTRING_LIST *szHostNames)
{
	int iCountDNSRecords = 0;
	DNS_STATUS status = 0;
	PDNS_RECORD  pDNSRecord = 0;
	PSTRING_LIST szHostNamesPrev = 0;
	PSTRING_LIST szHostNamesCurr = 0;

	status = DnsQuery(szSrvRecord, DNS_TYPE_SRV, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_WIRE_ONLY, NULL, &pDNSRecord, NULL);
	if (status == 0)
	{
		while (pDNSRecord != 0)
		{
			if (pDNSRecord->wType == DNS_TYPE_SRV)
			{
				szHostNamesCurr = (PSTRING_LIST)malloc(sizeof(STRING_LIST));
				szHostNamesCurr->szName = _strdup(pDNSRecord->Data.SRV.pNameTarget);
				szHostNamesCurr->next = szHostNamesPrev;
				szHostNamesPrev = szHostNamesCurr;
				iCountDNSRecords++;
			}
			pDNSRecord = pDNSRecord->pNext;
		}
		*szHostNames = szHostNamesCurr;
	}
	else
	{
		printf("Failed to lookup SRV record. Returned error %d.\n", status);
		return -1;
	}
	return iCountDNSRecords;
}
#endif

#if defined __linux__ 
int get_hostnames_from_srv(char *szSrvRecord, PSTRING_LIST  *szHostNames)
{
	unsigned char nsResponse[MaxString];
	ns_msg hMessageData;
	ns_rr rrSrvDC;
	int iIndex = 0;
	int iLength = 0;
	int iRetCode = 0;
	char vDispBuffer[MaxString];
	PSTRING_LIST szHostNamesPrev = 0;
	PSTRING_LIST szHostNamesCurr = 0;
	int iCountDNSRecords = 0;

	iLength = res_search(szSrvRecord, C_IN, T_SRV, nsResponse, sizeof(nsResponse));
	if (iLength > 0) {
		iRetCode = ns_initparse(nsResponse, iLength, &hMessageData);
		if (iRetCode >= 0)
		{
			iLength = ns_msg_count(hMessageData, ns_s_an);
			if (iLength >= 0)
			{
				for (iIndex = 0; iIndex < iLength; iIndex++)
				{
					iRetCode = ns_parserr(&hMessageData, ns_s_an, iIndex, &rrSrvDC);
					if (iRetCode == 0)
					{
						ns_sprintrr(&hMessageData, &rrSrvDC, NULL, NULL, vDispBuffer, sizeof(vDispBuffer));
						if (ns_rr_type(rrSrvDC) == ns_t_srv)
						{
							char szHostName[MAXDNAME];
							dn_expand(ns_msg_base(hMessageData), ns_msg_base(hMessageData) + ns_msg_size(hMessageData), ns_rr_rdata(rrSrvDC) + (NS_INT16SZ * 3), szHostName, sizeof(szHostName));
							szHostNamesCurr = (PSTRING_LIST)malloc(sizeof(STRING_LIST));
							szHostNamesCurr->szName = strdup(szHostName);
							szHostNamesCurr->next = szHostNamesPrev;
							szHostNamesPrev = szHostNamesCurr;
							iCountDNSRecords++;
						}
						else
						{
							if (iVerbose) { printf("Resource Record not of tye SRV\n"); }
						}
					}
					else
					{
						if (iVerbose) { printf("Unable to parse DNS response. ns_parserr returned %d\n", iRetCode); }
					}
				}
				*szHostNames = szHostNamesCurr;
			}
			else
			{
				printf("Failed to get message count. Returned error %d.\n", iLength);
				return -1;
			}
		}
		else
		{
			printf("Unable to parse DNS response. ns_initparse returned error %d\n", iRetCode);
			return -1;
		}
	}
	else
	{
		printf("Failed to lookup SRV record. Returned error %d.\n", iLength);
		return -1;
	}
	return iCountDNSRecords;
}

#endif

int free_pstring_list(PSTRING_LIST  szNames)
{
	PSTRING_LIST szNext;
	while (szNames != NULL)
	{
		free(szNames->szName);
		szNext = szNames;
		szNames = szNames->next;
		free(szNext);
	}
	return 0;
}

int print_usage(char* szBinaryName)
{
	printf("%s performs the DCLocator Process\n", szBinaryName);
	printf("Usage:\n");
	printf("%s [-v] -d DomainName \n", szBinaryName);
	printf("-v:\t\tVerbose Output\n");
	printf("-d domain:\tDomain to discover Domain Controllers for\n");
	printf("Example:\n");
	printf("%s -v -d contoso.com\n", szBinaryName);
	return 0;
}

int print_dc_flags(int iDCFlags)
{
	printf("Domain Controller Features:");
	if (DS_PDC_FLAG & iDCFlags) printf("PDC ");
	if (DS_GC_FLAG & iDCFlags) printf("GC ");
	if (DS_LDAP_FLAG & iDCFlags) printf("LDAP ");
	//if (DS_DS_FLAG & iDCFlags) printf("DC ");
	//if (DS_KDC_FLAG & iDCFlags) printf("KDC ");
	//if (DS_TIMESERV_FLAG & iDCFlags) printf("Win32TM ");
	if (DS_CLOSEST_FLAG & iDCFlags) printf("OptimalDC ");
	if (DS_WRITABLE_FLAG & iDCFlags) printf("RWDC ");
	if (DS_SELECT_SECRET_DOMAIN_6_FLAG & iDCFlags) printf("RODC ");
	//if (DS_WS_FLAG & iDCFlags) printf("ADWS ");
	//if (DS_FULL_SECRET_DOMAIN_6_FLAG & iDCFlags) printf("RW2008+ ");
	//if (DS_DS_8_FLAG & iDCFlags) printf("2012+ ");
	//if (DS_DS_9_FLAG & iDCFlags) printf("2012R2+ ");
	printf("\n");
	return 0;
}

int get_dc_topology(char * szDomainName, char* szDomainControllerName, char** szClientSiteName,
	char** szServerSiteName, char** szForestName, char** szServerDomainName, char** szServerFQDNName,
	char** szServerNetBIOSDomainName, char** szServerNetBIOSName, char** szDCDomainGUID, unsigned int *uiDCFlags)
{
	unsigned long ulRetcode = 0;
	LDAP * pLd = 0;
	LDAPMessage *res = 0;
	LDAPMessage *searchRes = 0;
	struct berval ** bVal = 0;
	PLDAP_PING_RESPONSE pldap_ping_response;
	char szLabel[MaxString];
	int offset = 0;
	char szDomainGUID[MaxString];
	char szDomainGUIDStringPartial[MaxString];
	const char  *attrs[2];
	attrs[0] = "netlogon";
	attrs[1] = '\0';
	char szLDAPFilter[MaxString];
	pLd = ldap_init((char*)szDomainControllerName, 389);
	ulRetcode = ldap_simple_bind_s(pLd, NULL, NULL);

	if (ulRetcode == 0)
	{
		strcpy(szLDAPFilter, "(&(DnsDomain=");
		strcat(szLDAPFilter, szDomainName);
		strcat(szLDAPFilter, ")(NtVer=\\04\\00\\00\\00))");
		//LDAP Filter format "(&(DnsDomain=contoso.com)(NtVer=\\04\\00\\00\\00))"
		ulRetcode = ldap_search_s(pLd, "", LDAP_SCOPE_BASE, (char*)szLDAPFilter, (char **)attrs, 0, &res);
		if (ulRetcode == 0)
		{
			searchRes = ldap_first_entry(pLd, res);
			if (searchRes == 0)
			{
				printf("Failed to retrieve AD Topology, check your domain name and try again\n");
				return -2;
			}
			bVal = ldap_get_values_len(pLd, searchRes, (char*)attrs[0]);
			pldap_ping_response = (PLDAP_PING_RESPONSE)bVal[0]->bv_val;
			//printf("Opcode: %d\n", pldap_ping_response->opcode);
			//printf("Sbz: %d\n", pldap_ping_response->Sbz);
			*uiDCFlags = pldap_ping_response->Flags;
			snprintf(szDomainGUID, MaxString, "%x", pldap_ping_response->Data1);
			strcat(szDomainGUID, "-");
			snprintf(szDomainGUIDStringPartial, MaxString, "%x", pldap_ping_response->Data2);
			strcat(szDomainGUID, szDomainGUIDStringPartial);
			strcat(szDomainGUID, "-");
			snprintf(szDomainGUIDStringPartial, MaxString, "%x", pldap_ping_response->Data3);
			strcat(szDomainGUID, szDomainGUIDStringPartial);
			strcat(szDomainGUID, "-");
			snprintf(szDomainGUIDStringPartial, MaxString, "%x", ntohs(pldap_ping_response->Data4));
			strcat(szDomainGUID, szDomainGUIDStringPartial);
			strcat(szDomainGUID, "-");
			snprintf(szDomainGUIDStringPartial, MaxString, "%x", ntohs(pldap_ping_response->Data5));
			strcat(szDomainGUID, szDomainGUIDStringPartial);
			snprintf(szDomainGUIDStringPartial, MaxString, "%x", ntohs(pldap_ping_response->Data6));
			strcat(szDomainGUID, szDomainGUIDStringPartial);
			snprintf(szDomainGUIDStringPartial, MaxString, "%x", ntohs(pldap_ping_response->Data7));
			strcat(szDomainGUID, szDomainGUIDStringPartial);
			*szDCDomainGUID = strdup(szDomainGUID);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szForestName = strdup(szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szServerDomainName = strdup(szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szServerFQDNName = strdup(szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szServerNetBIOSDomainName = strdup(szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szServerNetBIOSName = strdup(szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			//printf("User Name: %s\n", szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szServerSiteName = strdup(szLabel);
			offset = getlabelfromutf8(szLabel, pldap_ping_response->UTF8message, offset);
			*szClientSiteName = strdup(szLabel);
		}
		else
		{
			if (iVerbose) { printf("Failed to search Active Directory LDAP Server, returned error %d\n", ulRetcode); }
			return -1;
		}
	}
	else
	{
		if (iVerbose) { printf("Failed to conect to Active Directory LDAP Interface, returned error %d\n", ulRetcode); }
		return -1;
	}
	return 0;
}

int dclocator(char* szDomainName)
{
	PSTRING_LIST szHostNames = 0;
	PSTRING_LIST szHostNamesCurr = 0;
	char * szClientSiteName = 0;
	char* szServerSiteName = 0;
	char* szForestName = 0;
	char* szServerDomainName = 0;
	char* szServerFQDNName = 0;
	char* szServerNetBIOSDomainName = 0;
	char* szServerNetBIOSName = 0;
	char* szDCDomainGUID = 0;
	unsigned int uiDCFlags = 0;
	int bGotClientADSite = 0;
	int bGotADForestRoot = 0;
	int iDomainControllersFound = 0;
	char szDomainLDAPSRV[MaxString];
	char szDomainSiteLDAPSRV[MaxString];

	//scan Domain Controllers
	//determine AD Site Name
	strcpy(szDomainLDAPSRV, "_ldap._tcp.dc._msdcs.");
	strcat(szDomainLDAPSRV, szDomainName);
	if (iVerbose) { printf("Searching for Domain Controllers:%s\n", szDomainLDAPSRV); }
	iDomainControllersFound = get_hostnames_from_srv(szDomainLDAPSRV, &szHostNames);

	if (iDomainControllersFound > 0)
	{
		if (iVerbose) { printf("Domain Controllers Found in Domain:%d\n", iDomainControllersFound); }
		szHostNamesCurr = szHostNames;
		while ((szHostNamesCurr != 0) && (bGotClientADSite == 0))
		{
			if (iVerbose) { printf("Sending LDAP Ping to:%s\n", szHostNamesCurr->szName); }
			if (get_dc_topology(szDomainName, szHostNamesCurr->szName, &szClientSiteName, &szServerSiteName, &szForestName,
				&szServerDomainName, &szServerFQDNName, &szServerNetBIOSDomainName, &szServerNetBIOSName, &szDCDomainGUID, &uiDCFlags) == 0)
			{
				printf("Forest Name:%s\n", szForestName);
				printf("Domain Name:%s\n", szDomainName);
				printf("Domain NetBIOS Name:%s\n", szServerNetBIOSDomainName);
				printf("Server NetBIOS Name:%s\n", szServerNetBIOSName);
				printf("Domain GUID:%s\n", szDCDomainGUID);
				printf("Client Site:%s\n", szClientSiteName);
				
				bGotClientADSite = 1;
			}
			else
			{
				printf("Unavailable DC:%s\n", szHostNamesCurr->szName);
			}
			szHostNamesCurr = szHostNamesCurr->next;
		}
	}

	if (bGotClientADSite == 0)
	{
		printf("Unrecoverable Failure: Unable to determine client AD site. All Domain Controllers polled are unresponsive.\n");
		return -1;
	}

	if (strlen(szClientSiteName) == 0)
	{
		printf("Unrecoverable Failure: Active Directory does not have a subnet that corresponds to this machine's IP Address\n");
		return -1;
	}

	free_pstring_list(szHostNames);
	
	//scan Domain Controllers in Site
	//Connect to each and determine suitability.
	strcpy(szDomainSiteLDAPSRV, "_ldap._tcp.");
	strcat(szDomainSiteLDAPSRV, szClientSiteName);
	strcat(szDomainSiteLDAPSRV, "._sites.");
	strcat(szDomainSiteLDAPSRV, szDomainName);
	if (iVerbose) { printf("Searching for Domain Controllers:%s\n", szDomainSiteLDAPSRV); }
	iDomainControllersFound = get_hostnames_from_srv(szDomainSiteLDAPSRV, &szHostNames);
	if (iDomainControllersFound > 0)
	{
		if (iVerbose) { printf("Domian Controllers Found in site:%d\n", iDomainControllersFound); }
		szHostNamesCurr = szHostNames;
		while (szHostNamesCurr != 0)
		{
			if (iVerbose) { printf("Sending LDAP Ping to:%s\n", szHostNamesCurr->szName); }
			if (get_dc_topology(szDomainName, szHostNamesCurr->szName, &szClientSiteName, &szServerSiteName, &szForestName,
				&szServerDomainName, &szServerFQDNName, &szServerNetBIOSDomainName, &szServerNetBIOSName, &szDCDomainGUID, &uiDCFlags) == 0)
			{
				if (DS_CLOSEST_FLAG & uiDCFlags)
				{
					printf("Optimal DC:%s\n", szServerFQDNName);
					if (iVerbose) { print_dc_flags(uiDCFlags); }
					if (iVerbose) { printf("Server Site:%s\n", szServerSiteName); }
				}
			}
			else
			{
				printf("Unavailable DC:%s\n", szHostNamesCurr->szName);
			}
			szHostNamesCurr = szHostNamesCurr->next;
		}
	}
	free_pstring_list(szHostNames);
	return 0;
}

int main(int argc, char* argv[])
{
	int iArgLoop = 1;
	char * szDomainName = 0;

	while (iArgLoop < argc)
	{
		if (strcmp(argv[iArgLoop], "-v") == 0)
		{
			iVerbose = 1;
		}

		if (strcmp(argv[iArgLoop], "-d") == 0)
		{
			szDomainName = strdup(argv[iArgLoop + 1]);
			iArgLoop++;
		}
		iArgLoop++;
	}
	if (szDomainName != 0)
	{
		if (iVerbose) { printf("Starting Discovery for Active Directory Domain:%s\n", szDomainName); }
		dclocator(szDomainName);
	}
	else
	{
		print_usage(argv[0]);
	}
	return 0;
}


