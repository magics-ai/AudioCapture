/*
 * Oreka -- A media capture and retrieval platform
 * 
 * Copyright (C) 2005, orecx LLC
 *
 * http://www.orecx.com
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 * Please refer to http://www.gnu.org/copyleft/gpl.html
 *
 */
#pragma warning( disable: 4786 ) // disables truncated symbols in browse-info warning
#define _WINSOCKAPI_		// prevents the inclusion of winsock.h

#include "Utils.h"
#include "AudioCapture.h"
#include "VoIpSession.h"
#include "AudioCapturePlugin.h"
#include "AudioCapturePluginCommon.h"
#include <list>
#include "ConfigManager.h"
#include "VoIpConfig.h"

#include "MemUtils.h"
#include <boost/algorithm/string/predicate.hpp>
#include "../common/DtmfHandling.h"

extern AudioChunkCallBackFunction g_audioChunkCallBack;
extern CaptureEventCallBackFunction g_captureEventCallBack;

#define CONFERENCE_TRANSFER_TRACKING_TAG_KEY "orig-orkuid"

#ifdef TESTING
	VoIpSessions* VoIpSessionsSingleton::voipSessions = NULL;
#endif

VoIpSession::VoIpSession(CStdString& trackingId) : OrkSession(&DLLCONFIG),
	m_hasReceivedCallInfo(false),
	m_creationDate()
{
	m_startWhenReceiveS2 = false;
	m_trackingId = trackingId;
	m_lastUpdated = time(NULL);
	m_skinnyLastCallInfoTime = m_creationDate;
	m_sipLastInvite = m_creationDate;
	m_log = Logger::getLogger("rtpsession");
	m_direction = CaptureEvent::DirUnkn;
	m_localSide = CaptureEvent::LocalSideUnkn;
	m_protocol = ProtUnkn;
	m_numRtpPackets = 0;
	m_numIgnoredRtpPackets = 0;
	m_metadataProcessed = false;
	m_started = false;
	m_stopped = false;
	m_onHold = false;
	if(CONFIG.m_lookBackRecording == false)
	{
		m_keepRtp = false;
	}
	m_nonLookBackSessionStarted = false;
	m_hasDuplicateRtp = false;
	m_highestRtpSeqNumDelta = 0;
	m_minRtpSeqDelta = (double)DLLCONFIG.m_rtpDiscontinuityMinSeqDelta;
	m_minRtpTimestampDelta = (double)DLLCONFIG.m_rtpDiscontinuityMinSeqDelta * 160;		// arbitrarily based on 160 samples per packet (does not need to be precise)
	m_skinnyPassThruPartyId = 0;
	memset(m_localMac, 0, sizeof(m_localMac));
	memset(m_remoteMac, 0, sizeof(m_remoteMac));
	m_rtcpLocalParty = false;
	m_rtcpRemoteParty = false;
	m_remotePartyReported = false;
	m_localPartyReported = false;
	m_rtpIp.s_addr = 0;
	m_skinnyLineInstance = 0;
	m_onDemand = false;
	m_lastRtpStreamStart = 0;
	m_rtpNumMissingPkts = 0;
	m_rtpNumSeqGaps = 0;
	m_holdDuration = 0;
	m_ipAndPort = 0;
	m_isCallPickUp = false;
	m_lastKeepAlive = time(NULL);
	m_numAlienRtpPacketsS1 = 0;
	m_numAlienRtpPacketsS2 = 0;
	m_ssrcCandidate = -1;
	m_mappedS1S2 =  false;
	m_orekaRtpPayloadType = 0;
}

void VoIpSession::Stop()
{
	CStdString logMsg;
	logMsg.Format("[%s] %s Session stop, numRtpPkts:%d dupl:%d seqDelta:%d rtpNumMissingPkts:%d rtpNumSeqGaps:%d lastUpdated:%u", m_trackingId, m_capturePort, m_numRtpPackets, m_hasDuplicateRtp, m_highestRtpSeqNumDelta, m_rtpNumMissingPkts, m_rtpNumSeqGaps, m_lastUpdated);
	LOG4CXX_INFO(m_log, logMsg);

	if(m_started && !m_stopped)
	{
		// Report local side
		if(m_lastRtpPacketSide1.get())
		{
			if(!MatchesReferenceAddresses(m_lastRtpPacketSide1->m_sourceIp))
			{
				m_localSide = CaptureEvent::LocalSideSide1;
			}
			else
			{
				VoIpEndpointInfoRef endpoint;

				endpoint = VoIpSessionsSingleton::instance()->GetVoIpEndpointInfoByIp(&m_lastRtpPacketSide1->m_sourceIp);
				if(endpoint.get())
				{
					m_localSide = CaptureEvent::LocalSideSide1;
				}
			}
		}

		if(m_lastRtpPacketSide2.get())
		{
			if(!MatchesReferenceAddresses(m_lastRtpPacketSide2->m_sourceIp))
			{
				if(m_localSide == CaptureEvent::LocalSideSide1)
				{
					m_localSide = CaptureEvent::LocalSideBoth;
				}
				else
				{
					m_localSide = CaptureEvent::LocalSideSide2;
				}
			}
			else
			{
				VoIpEndpointInfoRef endpoint;

				endpoint = VoIpSessionsSingleton::instance()->GetVoIpEndpointInfoByIp(&m_lastRtpPacketSide2->m_sourceIp);
				if(endpoint.get())
				{
					if(m_localSide == CaptureEvent::LocalSideSide1)
					{
						m_localSide = CaptureEvent::LocalSideBoth;
					}
					else
					{
						m_localSide = CaptureEvent::LocalSideSide2;
					}
				}
			}
		}

		if(DLLCONFIG.m_urlExtractorEnable == true)
		{
			VoIpEndpointInfoRef endpoint;
			endpoint = VoIpSessionsSingleton::instance()->GetVoIpEndpointInfo(m_localIp, 0);
			if(!endpoint.get())
			{
				endpoint = VoIpSessionsSingleton::instance()->GetVoIpEndpointInfo(m_remoteIp, 0);
			}

			if(endpoint.get())
			{
				std::map<CStdString, UrlExtractionValueRef>::iterator it;
				it = endpoint->m_urlExtractionMap.find(DLLCONFIG.m_remotePartyUseExtractedKey);
				if(it != endpoint->m_urlExtractionMap.end())
				{
					if((it->second->m_timestamp >= m_creationDate.sec()) && (it->second->m_timestamp <= m_lastUpdated))
					{
						m_remoteParty = it->second->m_value;
						CaptureEventRef event(new CaptureEvent());
						event->m_type = CaptureEvent::EtRemoteParty;
						event->m_value = m_remoteParty;
						g_captureEventCallBack(event, m_capturePort);
					}
				}
			}

		}

		CaptureEventRef event(new CaptureEvent);
		event->m_type = CaptureEvent::EtLocalSide;
		event->m_value = CaptureEvent::LocalSideToString(m_localSide);
		g_captureEventCallBack(event, m_capturePort);

		CaptureEventRef stopEvent(new CaptureEvent);
		stopEvent->m_type = CaptureEvent::EtStop;
		stopEvent->m_timestamp = m_lastUpdated;
		g_captureEventCallBack(stopEvent, m_capturePort);
		m_stopped = true;
	}
}

bool VoIpSession::Stopped()
{
	return m_stopped;
}

RtpPacketInfoRef VoIpSession::GetLastRtpPacket()
{
	return m_lastRtpPacket;
}

void VoIpSession::ReportRtcpSrcDescription(RtcpSrcDescriptionPacketInfoRef& rtcpInfo)
{
}

void VoIpSession::Start()
{
	m_beginDate = time(NULL);
	if(m_started == false)
	{
		GenerateOrkUid();
	}
        LOG4CXX_INFO(m_log, "VoIpSession::Start");
	m_started = true;
	CaptureEventRef startEvent(new CaptureEvent);
	startEvent->m_type = CaptureEvent::EtStart;
	startEvent->m_timestamp = m_beginDate;
	startEvent->m_value = m_trackingId;
        startEvent->ip = ip;
        startEvent->ext = ext;
	CStdString timestamp = IntToString(startEvent->m_timestamp);
	LOG4CXX_INFO(m_log,  "[" + m_trackingId + "] " + m_capturePort + " " + ProtocolToString(m_protocol) + " Session start, timestamp:" + timestamp);
	g_captureEventCallBack(startEvent, m_capturePort);
}

void VoIpSession::GenerateOrkUid()
{
	apr_time_exp_t texp;
   	apr_time_exp_lt(&texp, m_beginDate*1000*1000);
	int month = texp.tm_mon + 1;				// january=0, decembre=11
	int year = texp.tm_year + 1900;
	m_orkUid.Format("%.4d%.2d%.2d_%.2d%.2d%.2d_%s", year, month, texp.tm_mday,texp.tm_hour, texp.tm_min, texp.tm_sec, m_trackingId);
}


void VoIpSession::ProcessMetadataRawRtp(RtpPacketInfoRef& rtpPacket)
{
	bool sourceIsLocal = true;

	if(DLLCONFIG.IsMediaGateway(rtpPacket->m_sourceIp))
	{
		if(DLLCONFIG.IsMediaGateway(rtpPacket->m_destIp))
		{
			// media gateway to media gateway
			sourceIsLocal = false;
		}
		else if (DLLCONFIG.IsPartOfLan(rtpPacket->m_destIp))
		{
			// Media gateway to internal
			sourceIsLocal = false;
		}
		else
		{
			// Media gateway to external
			sourceIsLocal = true;
		}
	}
	else if (DLLCONFIG.IsPartOfLan(rtpPacket->m_sourceIp))
	{
		// source address is internal
		sourceIsLocal = true;
	}
	else
	{
		// source address is external
		sourceIsLocal = false;
	}

	char szSourceIp[16];
	inet_ntopV4(AF_INET, (void*)&rtpPacket->m_sourceIp, szSourceIp, sizeof(szSourceIp));
	char szDestIp[16];
	inet_ntopV4(AF_INET, (void*)&rtpPacket->m_destIp, szDestIp, sizeof(szDestIp));

	if(DLLCONFIG.m_sangomaEnable)
	{
		m_capturePort = IntToString(rtpPacket->m_sourcePort % 1000);
	}
	else
	{
		m_capturePort = m_trackingId;
	}

	if(sourceIsLocal)
	{
		if(!m_rtcpLocalParty)
		{
	                /* With Raw RTP, the local party is not obtained through any intelligent
        	         * signalling so we should probably do this check here? */
                	if(DLLCONFIG.m_useMacIfNoLocalParty)
	                {
        	                MemMacToHumanReadable((unsigned char*)rtpPacket->m_sourceMac, m_localParty);
                	}
	                else
        	        {
				CStdString lp(szSourceIp);
                	        m_localParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(lp);
	                }
		}
		if(!m_rtcpRemoteParty)
		{
			CStdString rp(szDestIp);
			m_remoteParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(rp);
		}

		m_localIp = rtpPacket->m_sourceIp;
		m_remoteIp = rtpPacket->m_destIp;
		memcpy(m_localMac, rtpPacket->m_sourceMac, sizeof(m_localMac));
		memcpy(m_remoteMac, rtpPacket->m_destMac, sizeof(m_remoteMac));
	}
	else
	{
		if(!m_rtcpLocalParty)
		{
	                /* With Raw RTP, the local party is not obtained through any intelligent
        	         * signalling so we should probably do this check here? */
			if(DLLCONFIG.m_useMacIfNoLocalParty)
        	        {
                	        MemMacToHumanReadable((unsigned char*)rtpPacket->m_destMac, m_localParty);
			}
			else
			{
				CStdString lp(szDestIp);
				m_localParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(lp);
			}
		}
		if(!m_rtcpRemoteParty)
		{
			CStdString rp(szSourceIp);
			m_remoteParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(rp);
		}

		m_localIp = rtpPacket->m_destIp;
		m_remoteIp = rtpPacket->m_sourceIp;
                memcpy(m_localMac, rtpPacket->m_destMac, sizeof(m_localMac));
                memcpy(m_remoteMac, rtpPacket->m_sourceMac, sizeof(m_remoteMac));
	}
}

bool VoIpSession::MatchesSipDomain(CStdString& domain)
{
	return false;
}

bool VoIpSession::IsInSkinnyReportingList(CStdString item)
{
	return false;
}

void VoIpSession::ProcessMetadataSipIncoming()
{
}

void VoIpSession::ProcessMetadataSipOutgoing()
{
}

void VoIpSession::UpdateMetadataSkinny()
{
}

void VoIpSession::UpdateMetadataSipOnRtpChange(RtpPacketInfoRef& rtpPacket, bool sourceRtpAddressIsNew)
{
}

bool VoIpSession::MatchesReferenceAddresses(struct in_addr inAddr)
{
	return DLLCONFIG.m_sipDirectionReferenceIpAddresses.Matches(inAddr);
}

void VoIpSession::ProcessMetadataSip(RtpPacketInfoRef& rtpPacket)
{

}

void VoIpSession::ProcessMetadataSkinny(RtpPacketInfoRef& rtpPacket)
{
}


void VoIpSession::ReportMetadata()
{
        return;
	CStdString logMsg;
	char szLocalIp[16];
	inet_ntopV4(AF_INET, (void*)&m_localIp, szLocalIp, sizeof(szLocalIp));
	char szRemoteIp[16];
	inet_ntopV4(AF_INET, (void*)&m_remoteIp, szRemoteIp, sizeof(szRemoteIp));

	if(DLLCONFIG.m_localPartyForceLocalIp)
	{
		CStdString lp(szLocalIp);
		m_localParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(lp);
	}
	// Check if we don't have the local party based on the endpoint IP address
	else if(m_localParty.IsEmpty())
	{
		if(m_protocol == ProtSkinny)
		{
			VoIpEndpointInfoRef endpointInfo = VoIpSessionsSingleton::instance()->GetVoIpEndpointInfo(m_endPointIp, m_endPointSignallingPort);
			if(endpointInfo.get())
			{
				m_localParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(endpointInfo->m_extension);
			}
		}
	}

	// Make sure Local Party is always reported
	if(m_localParty.IsEmpty())
	{
		if(DLLCONFIG.m_useMacIfNoLocalParty)
		{
			MemMacToHumanReadable((unsigned char*)m_localMac, m_localParty);
		}
		else
		{
			CStdString lp(szLocalIp);
			m_localParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(lp);
		}
	}

	if(DLLCONFIG.m_localPartyForceLocalMac)
	{
		m_localParty = "";
		MemMacToHumanReadable((unsigned char*)m_localMac, m_localParty);
		m_localParty = VoIpSessionsSingleton::instance()->GetLocalPartyMap(m_localParty);
	}

	//If this session is Call Pick Up, then we revert the direction
	if(m_isCallPickUp)
	{
		if(m_direction == CaptureEvent::DirIn)
		{
			m_direction = CaptureEvent::DirOut;
		}
		else
		{
			m_direction = CaptureEvent::DirIn;
		}
		LOG4CXX_INFO(m_log, "[" + m_trackingId + "] " + "is Sip Service Call Pick Up session, reverted call direction");
	}

	if (DLLCONFIG.m_localPartyNameMapEnable) {
		static std::map<CStdString, CStdString> s_localPartyNameMap;
		CStdString localIp(szLocalIp);
		CStdString tempLocalPartyName = s_localPartyNameMap[localIp];

		if (m_localPartyName != m_localParty && !(m_localPartyName.length()==0) && m_localPartyName != tempLocalPartyName) {
			s_localPartyNameMap[localIp] = m_localPartyName;

			logMsg.Format("[%s] Saved localPartyName:%s localIp:%s in localPartyNameMap",m_capturePort,m_localPartyName,localIp);
			LOG4CXX_DEBUG(m_log, logMsg);
		}
		else if (!(tempLocalPartyName.length()==0) && m_localPartyName != tempLocalPartyName) {
			logMsg.Format("[%s] Retrieved localPartyName:%s for localIp:%s from localPartyNameMap, old name:%s",m_capturePort,tempLocalPartyName,localIp,m_localPartyName);
			LOG4CXX_INFO(m_log, logMsg);

			m_localPartyName = tempLocalPartyName;
		}
	}

	// Report Local party
	CaptureEventRef event(new CaptureEvent());
	event->m_type = CaptureEvent::EtLocalParty;
	// TODO, we might consider deprecating m_skinnyNameAsLocalParty in favour of m_localPartyUseName at some point
	if( ( m_protocol == ProtSkinny && DLLCONFIG.m_skinnyNameAsLocalParty == true && m_localPartyName.size() )   || 
		( (DLLCONFIG.m_partiesUseName || DLLCONFIG.m_localPartyUseName) == true && m_localPartyName.size() )		 )
	{
		if(DLLCONFIG.m_localPartyAddLocalIp == true)
		{
			char szLocalIp[16];
			inet_ntopV4(AF_INET, (void*)&m_localIp, szLocalIp, sizeof(szLocalIp));
			m_localPartyName.Format("%s@%s", m_localPartyName, szLocalIp);
		}
		event->m_value = m_localPartyName;
	}
	else
	{
		if(DLLCONFIG.m_localPartyAddLocalIp == true)
		{
			char szLocalIp[16];
			inet_ntopV4(AF_INET, (void*)&m_localIp, szLocalIp, sizeof(szLocalIp));
			m_localParty.Format("%s@%s", m_localParty, szLocalIp);
		}
		event->m_value = m_localParty;
	}
	g_captureEventCallBack(event, m_capturePort);
	m_localPartyReported = true;

	// Report remote party
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtRemoteParty;
	if(DLLCONFIG.m_partiesUseName == true && m_remotePartyName.size())
	{
		event->m_value = m_remotePartyName;
	}
	else
	{
		event->m_value = m_remoteParty;
	}
	g_captureEventCallBack(event, m_capturePort);
	m_remotePartyReported = true;

	// Report local entry point
	if(m_localEntryPoint.size())
	{
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtLocalEntryPoint;
		event->m_value = m_localEntryPoint;
		g_captureEventCallBack(event, m_capturePort);
	}

	if(DLLCONFIG.m_sipReportNamesAsTags == true)
	{
		CStdString key, value;

		key = "localname";
		value = m_localPartyName;
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtKeyValue;
		event->m_key = key;
		event->m_value = value;
		g_captureEventCallBack(event, m_capturePort);

		key = "remotename";
		value = m_remotePartyName;
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtKeyValue;
		event->m_key = key;
		event->m_value = value;
		g_captureEventCallBack(event, m_capturePort);
	}

	// Report direction
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtDirection;
	event->m_value = CaptureEvent::DirectionToString(m_direction);
	g_captureEventCallBack(event, m_capturePort);

	// Report Local IP address
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtLocalIp;
	event->m_value = szLocalIp;
	g_captureEventCallBack(event, m_capturePort);

	// Report Remote IP address
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtRemoteIp;
	event->m_value = szRemoteIp;
	g_captureEventCallBack(event, m_capturePort);

	// Report OrkUid
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtOrkUid;
	event->m_value = m_orkUid;
	g_captureEventCallBack(event, m_capturePort);

	// Report native Call ID
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtCallId;
	event->m_value = m_callId;
	g_captureEventCallBack(event, m_capturePort);

	if(m_onDemand == true)
	{
		// Report ondemand status
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtKeyValue;
		event->m_key  = CStdString("ondemand");
		event->m_value = CStdString("true");
		g_captureEventCallBack(event, m_capturePort);
	}

	// Report extracted fields
	for(std::map<CStdString, CStdString>::iterator pair = m_tags.begin(); pair != m_tags.end(); pair++)
	{
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtKeyValue;
		event->m_key = pair->first;
		event->m_value = pair->second;
		g_captureEventCallBack(event, m_capturePort);
	}

	// Report end of metadata
	event.reset(new CaptureEvent());
	event->m_type = CaptureEvent::EtEndMetadata;
	g_captureEventCallBack(event, m_capturePort);
}

void VoIpSession::GoOnHold(time_t onHoldTime)
{
}

void VoIpSession::GoOffHold(time_t offHoldTime)
{
}

// Returns false if the packet does not belong to the session (RTP timestamp discontinuity)
bool VoIpSession::AddRtpPacket(RtpPacketInfoRef& rtpPacket)
{
	CStdString logMsg;
	unsigned char channel = 0;

	if( m_metadataProcessed == false )
	{
		m_metadataProcessed = true;
		
		if(m_protocol == ProtRawRtp)
		{
			ProcessMetadataRawRtp(rtpPacket);
		}
	}

	if(!m_keepRtp)
	{
		if(m_nonLookBackSessionStarted == true && (time(NULL) - m_lastKeepAlive > 1) )
		{
			// In case of non-lookback send a keep-alive every second
			CaptureEventRef event(new CaptureEvent());
			event->m_type = CaptureEvent::EtUnknown;
			event->m_value = "";

			m_lastKeepAlive = time(NULL);
			g_captureEventCallBack(event,m_capturePort);
		}

		m_lastUpdated = rtpPacket->m_arrivalTimestamp;
		m_numIgnoredRtpPackets++;
		return true;
	}

	if(CONFIG.m_lookBackRecording == false && m_numRtpPackets == 0)
	{
		if (CONFIG.m_discardUnidirectionalCalls ) {
			m_startWhenReceiveS2 = true;
		}
		else {
                        LOG4CXX_INFO(m_log, " xxxxxxxxxxxxxxxxxx call VoIpSession Start");
			Start();
			ReportMetadata();
		}
	}



	m_lastRtpPacket = rtpPacket;

	if(m_lastRtpPacketSide1.get() == NULL)
	{
                LOG4CXX_INFO(m_log, " 11111111111111111111");
		// First RTP packet for side 1
		m_lastRtpPacketSide1 = rtpPacket;
		channel = 1;

		if(m_log->isInfoEnabled())
		{
			rtpPacket->ToString(logMsg);
			logMsg =  "[" + m_trackingId + "] 1st packet s1: " + logMsg;
			LOG4CXX_INFO(m_log, logMsg);
		}
	}
	else
	{
                LOG4CXX_INFO(m_log, " 222222222222222222222");
		if( rtpPacket->m_ssrc == m_lastRtpPacketSide1->m_ssrc && m_lastRtpPacketSide1->m_destIp.s_addr == rtpPacket->m_destIp.s_addr )
		{

			LOG4CXX_INFO(m_log, " 333333333333333333");
			// Subsequent RTP packet for side 1
			if(rtpPacket->m_timestamp == m_lastRtpPacketSide1->m_timestamp)
			{
				m_hasDuplicateRtp = true;
				return true;	// dismiss duplicate RTP packet
			}
			else
			{
                                LOG4CXX_INFO(m_log, "33333--- 11111");
				double seqNumDelta = (double)rtpPacket->m_seqNum - (double)m_lastRtpPacketSide1->m_seqNum;
				if(DLLCONFIG.m_rtpDiscontinuityDetect)
				{

					LOG4CXX_INFO(m_log, "33333--- 22222");
					double timestampDelta = (double)rtpPacket->m_timestamp - (double)m_lastRtpPacketSide1->m_timestamp;
					if(	abs(seqNumDelta) > m_minRtpSeqDelta  &&
						abs(timestampDelta) > m_minRtpTimestampDelta)	
					{
						logMsg.Format("[%s] RTP discontinuity s1: before: seq:%u ts:%u after: seq:%u ts:%u", 
							m_trackingId, m_lastRtpPacketSide1->m_seqNum, m_lastRtpPacketSide1->m_timestamp, 
							rtpPacket->m_seqNum, rtpPacket->m_timestamp);
						LOG4CXX_INFO(m_log, logMsg);
						return false;
					}
				}
				//In case of dialer session, rtp keeps on going even when the call is done
				//If we detect the pausing in rtp, we break the session
				int deltaTimestamp = rtpPacket->m_timestamp - m_lastRtpPacketSide1->m_timestamp;
				if(DLLCONFIG.m_rtpBreakupOnStreamPause == true && (abs(seqNumDelta) * 160) < deltaTimestamp)
				{

					LOG4CXX_INFO(m_log, "33333--- 3333");
					if((double)rtpPacket->m_seqNum < (double)m_lastRtpPacketSide1->m_seqNum)	//seq reset
					{
						seqNumDelta = 65536 - (double)m_lastRtpPacketSide1->m_seqNum + (double)rtpPacket->m_seqNum;
					}
					if((seqNumDelta * 160) < deltaTimestamp)
					{
						logMsg.Format("[%s] RTP stream pause detected, breaking up s1: before: seq:%u ts:%u after: seq:%u ts:%u",
									m_trackingId, m_lastRtpPacketSide1->m_seqNum, m_lastRtpPacketSide1->m_timestamp,
									rtpPacket->m_seqNum, rtpPacket->m_timestamp);
						LOG4CXX_INFO(m_log, logMsg);
						return false;
					}
				}

				if(seqNumDelta > (double)m_highestRtpSeqNumDelta)
				{

					LOG4CXX_INFO(m_log, "33333--- 444444444");
					m_highestRtpSeqNumDelta = (unsigned int)seqNumDelta;
				}

				if(seqNumDelta > 1)
				{
					LOG4CXX_INFO(m_log, "33333---5555555555");
					if(seqNumDelta <= DLLCONFIG.m_rtpSeqGapThreshold)
					{
					        LOG4CXX_INFO(m_log, "33333---66666");
						m_rtpNumSeqGaps += 1;
						m_rtpNumMissingPkts += ((unsigned int)seqNumDelta - 1);
					}
				}
			}
                        LOG4CXX_INFO(m_log, "33333-777777");
			m_lastRtpPacketSide1 = rtpPacket;
			channel = 1;
			m_numAlienRtpPacketsS1 = 0;
		}
		else
		{
                        LOG4CXX_INFO(m_log, "444444444444444444");
			if(m_lastRtpPacketSide2.get() == NULL)
			{
				// First RTP packet for side 2
				m_lastRtpPacketSide2 = rtpPacket;
				channel = 2;

				if(m_log->isInfoEnabled())
				{
					rtpPacket->ToString(logMsg);
					logMsg =  "[" + m_trackingId + "] 1st packet s2: " + logMsg;
					LOG4CXX_INFO(m_log, logMsg);
				}
				if (CONFIG.m_discardUnidirectionalCalls && m_startWhenReceiveS2) {

					LOG4CXX_INFO(m_log, " xxxxxxxxxxxxxxxxxx-1 call VoIpSession Start");
					Start();
					ReportMetadata();
				}
			}
			else
			{
				if(rtpPacket->m_ssrc == m_lastRtpPacketSide2->m_ssrc && m_lastRtpPacketSide2->m_destIp.s_addr == rtpPacket->m_destIp.s_addr)
				{
					// Subsequent RTP packet for side 2
					if(rtpPacket->m_timestamp == m_lastRtpPacketSide2->m_timestamp)
					{
						m_hasDuplicateRtp = true;
						return true;	// dismiss duplicate RTP packet
					}
					else
					{
						double seqNumDelta = (double)rtpPacket->m_seqNum - (double)m_lastRtpPacketSide2->m_seqNum;
						if(DLLCONFIG.m_rtpDiscontinuityDetect)
						{
							double timestampDelta = (double)rtpPacket->m_timestamp - (double)m_lastRtpPacketSide2->m_timestamp;
							if(	abs(seqNumDelta) > m_minRtpSeqDelta  &&
								abs(timestampDelta) > m_minRtpTimestampDelta)
							{
								logMsg.Format("[%s] RTP discontinuity s2: before: seq:%u ts:%u after: seq:%u ts:%u",
									m_trackingId, m_lastRtpPacketSide2->m_seqNum, m_lastRtpPacketSide2->m_timestamp,
									rtpPacket->m_seqNum, rtpPacket->m_timestamp);
								LOG4CXX_INFO(m_log, logMsg);
								return false;
							}
						}

						int deltaTimestamp = rtpPacket->m_timestamp - m_lastRtpPacketSide2->m_timestamp;
						if(DLLCONFIG.m_rtpBreakupOnStreamPause == true )
						{
							if((double)rtpPacket->m_seqNum < (double)m_lastRtpPacketSide2->m_seqNum)	//seq reset
							{
								seqNumDelta = 65536 - (double)m_lastRtpPacketSide2->m_seqNum + (double)rtpPacket->m_seqNum;
							}
							if((seqNumDelta * 160) < deltaTimestamp)
							{
								logMsg.Format("[%s] RTP stream pause detected, breaking up s2: before: seq:%u ts:%u after: seq:%u ts:%u",
										m_trackingId, m_lastRtpPacketSide2->m_seqNum, m_lastRtpPacketSide2->m_timestamp,
										rtpPacket->m_seqNum, rtpPacket->m_timestamp);
								LOG4CXX_INFO(m_log, logMsg);
								return false;
							}
						}

						if(seqNumDelta > (double)m_highestRtpSeqNumDelta)
						{
							m_highestRtpSeqNumDelta = (unsigned int)seqNumDelta;
						}
					}

					m_lastRtpPacketSide2 = rtpPacket;
					channel = 2;
					m_numAlienRtpPacketsS2 = 0;
				}
				else
				{
					// this packet does not match either s1 or s2 (on the basis of SSRC)
					if(m_ssrcCandidate == -1)
					{
						m_ssrcCandidate = rtpPacket->m_ssrc;
						m_ssrcCandidateTimestamp = (unsigned int)rtpPacket->m_arrivalTimestamp;
						rtpPacket->ToString(logMsg);
						logMsg.Format("[%s] ssrc candidate: %s", m_trackingId, logMsg);
						LOG4CXX_INFO(m_log, logMsg);
					}
					else if(rtpPacket->m_ssrc == m_ssrcCandidate)
					{
						m_ssrcCandidateTimestamp = (unsigned int)rtpPacket->m_arrivalTimestamp;
						m_numAlienRtpPacketsS1++;
						m_numAlienRtpPacketsS2++;
					}
					else
					{
						if((time(NULL) - m_ssrcCandidateTimestamp) > 2)
						{
							m_ssrcCandidate = -1;
							m_numAlienRtpPacketsS1 = 0;
							m_numAlienRtpPacketsS2 = 0;
							logMsg.Format("[%s] ssrc:0x%x candidate stopped", m_trackingId, rtpPacket->m_ssrc);
							LOG4CXX_INFO(m_log, logMsg);
						}
						if(DLLCONFIG.m_rtpLogAllSsrc ==  true)
						{
							std::map<unsigned int, int>::iterator it;
							it = m_loggedSsrcMap.find(rtpPacket->m_ssrc);
							if(it == m_loggedSsrcMap.end())
							{
								m_loggedSsrcMap.insert(std::make_pair(rtpPacket->m_ssrc, 1));
								logMsg.Format("[%s] detects unestablished ssrc:0x%x", m_trackingId, rtpPacket->m_ssrc);
								LOG4CXX_INFO(m_log, logMsg);
							}
						}
					}

					bool remapped = false;

					if(m_numAlienRtpPacketsS1 > 10)
					{
						// We have seen 10 alien packets and no s1 packets during the same period of time
						m_numAlienRtpPacketsS1 = 0;
						m_ssrcCandidate = -1;
						remapped = true;
						channel = 1;
						m_lastRtpPacketSide1 = rtpPacket;
						m_mappedS1S2 = false;

						rtpPacket->ToString(logMsg);
						logMsg.Format("[%s] s1 remapped to: %s", m_trackingId, logMsg);
						LOG4CXX_INFO(m_log, logMsg);
					}
					else if(m_numAlienRtpPacketsS2 > 10)
					{
						// We have seen 10 alien packets and no s2 packets during the same period of time
						m_numAlienRtpPacketsS2 = 0;
						m_ssrcCandidate = -1;
						remapped = true;
						channel = 2;
						m_lastRtpPacketSide2 = rtpPacket;
						m_mappedS1S2 = false;

						rtpPacket->ToString(logMsg);
						logMsg.Format("[%s] s2 remapped to: %s", m_trackingId, logMsg);
						LOG4CXX_INFO(m_log, logMsg);
					}
					else
					{
						// dismiss packet so that it does not disrupt the current established stream
						return true;
					}

					if (remapped)
					{
						m_lastRtpStreamStart = time(NULL);
					}
				}
			}
		}
	}

	if ( m_config->m_rtpS1S2MappingDeterministic && !m_mappedS1S2 && m_lastRtpPacketSide1.get() && m_lastRtpPacketSide2.get() ) {
		m_mappedS1S2 = true;
		if (m_protocol==ProtSip || m_protocol==ProtSkinny)
		if ( ShouldSwapChannels() ) {
			RtpPacketInfoRef tmpRtpPacketInfoRef = m_lastRtpPacketSide1;
			m_lastRtpPacketSide1 = m_lastRtpPacketSide2;
			m_lastRtpPacketSide2 = tmpRtpPacketInfoRef;
			channel = (channel%2)+1; // 1 if it was 2 , 2 if it was 1

			LOG4CXX_INFO(m_log, "[" + m_trackingId + "] deterministic audio channel mapping: swapped s1 and s2 because " + m_logMsg );
		}
	}

	m_numRtpPackets++;
	m_lastUpdated = rtpPacket->m_arrivalTimestamp;

	bool hasSourceAddress = m_rtpAddressList.HasAddressOrAdd(rtpPacket->m_sourceIp, rtpPacket->m_sourcePort);
	bool hasDestAddress = m_rtpAddressList.HasAddressOrAdd(rtpPacket->m_destIp, rtpPacket->m_destPort);
	if(	hasSourceAddress == false || hasDestAddress == false )
	{
		// A new RTP stream has been detected
		// (but RTP packets for this new stream will only start to be recorded when
		// the new stream is confirmed, see numAlienRtpPackets)
		// NOTE: only the first packet of a bidirectional RTP steam is logged here,
		// so for now, the log does not contain any trace of the other side until s2 is remapped.
		rtpPacket->ToString(logMsg);
		logMsg.Format("[%s] new RTP stream: %s", m_trackingId, logMsg);
		LOG4CXX_INFO(m_log, logMsg);

		if(m_protocol == ProtSip && m_started && DLLCONFIG.m_sipAllowMetadataUpdateOnRtpChange)	// make sure this only happens if ReportMetadata() already been called for the session
		{
			UpdateMetadataSipOnRtpChange(rtpPacket, hasDestAddress);
		}
	}

	if(m_log->isDebugEnabled())
	{
		CStdString debug;
		debug.Format("[%s] %s: Add RTP packet srcPort:%u dstPort:%u seq:%u ts:%u  arrival:%u ch:%d", m_trackingId, m_capturePort, rtpPacket->m_sourcePort, rtpPacket->m_destPort, rtpPacket->m_seqNum, rtpPacket->m_timestamp, rtpPacket->m_arrivalTimestamp, channel);
		LOG4CXX_DEBUG(m_log, debug);
	}

	if(m_protocol == ProtRawRtp && m_numRtpPackets == DLLCONFIG.m_rtpMinAmountOfPacketsBeforeStart)
	{
		// We've got enough packets to start the session.
		// For Raw RTP, the high number is to make sure we have a "real" raw RTP session, not a leftover from a SIP/Skinny session
		if(CONFIG.m_lookBackRecording == true) 
		{
			if(CONFIG.m_discardUnidirectionalCalls) {
				m_startWhenReceiveS2 = true;
			}
			else {

				LOG4CXX_INFO(m_log, " @@@ call VoIpSession Start");
				Start();
				ReportMetadata();
			}
		}

	}

	if(m_started)
	{
		CStdString payloadType;
	
		payloadType.Format("%d",rtpPacket->m_payloadType);

		for(std::list<CStdString>::iterator it = CONFIG.m_speexPayloadTypes.begin() ; it != CONFIG.m_speexPayloadTypes.end() ; it++)
		{
			if( *it == payloadType ) 
			{
				rtpPacket->m_payloadType = 66;
				break;
			}
		}

		AudioChunkDetails details;
		details.m_arrivalTimestamp = rtpPacket->m_arrivalTimestamp;
		details.m_numBytes = rtpPacket->m_payloadSize;
		details.m_timestamp = rtpPacket->m_timestamp;
		details.m_sequenceNumber = rtpPacket->m_seqNum;
		details.m_channel = 1; //channel;
		details.m_encoding = AlawAudio;
		details.m_numBytes = rtpPacket->m_payloadSize;
                //details.ip = rtpPacket->ip; 
                //details.ext = rtpPacket->ext;
		if(m_orekaRtpPayloadType != 0 && rtpPacket->m_payloadType >= 96)
		{
			details.m_rtpPayloadType = m_orekaRtpPayloadType;
		}
		else
		{
			details.m_rtpPayloadType = rtpPacket->m_payloadType;
		}
		AudioChunkRef chunk(new AudioChunk());
                //details --> chunk               
		chunk->SetBuffer(rtpPacket->m_payload, details);
                //CStdString logMsg;
                //logMsg.Format(" Add new AudioChunk to callback %s",m_capturePort);
                //LOG4CXX_INFO(m_log, logMsg);       
		g_audioChunkCallBack(chunk, m_capturePort);

	}
	return true;
}

void VoIpSession::ReportSipBye(SipByeInfoRef& bye)
{
}


bool IsNecExternal(SipInviteInfoRef& invite) {
	CStdString from_or_to = DLLCONFIG.m_sipDirectionReferenceIpAddresses.Matches(invite->m_senderIp)?invite->m_from:invite->m_to;

	if (MatchesStringList(from_or_to, DLLCONFIG.m_necVoipGatewayNames)) {
		return true;
	}

	return false;
}

void VoIpSession::ReportSipNotify(SipNotifyInfoRef& notify)
{
}

void VoIpSession::ReportSipInvite(SipInviteInfoRef& invite)
{
}

void VoIpSession::ReportSipInfo(SipInfoRef& info)
{
}

void VoIpSession::ReportSipRefer(SipReferRef& info)
{
}

void VoIpSession::ReportSipErrorPacket(SipFailureMessageInfoRef& info)
{
}

int VoIpSession::ProtocolToEnum(CStdString& protocol)
{
	int protocolEnum = ProtUnkn;
	if(protocol.CompareNoCase(PROT_RAW_RTP) == 0)
	{
		protocolEnum = ProtRawRtp;
	}
	else if (protocol.CompareNoCase(PROT_SIP) == 0)
	{
		protocolEnum = ProtSip;
	}
	else if (protocol.CompareNoCase(PROT_SKINNY) == 0)
	{
		protocolEnum = ProtSkinny;
	}
	return protocolEnum;
}

CStdString VoIpSession::ProtocolToString(int protocolEnum)
{
	CStdString protocolString;
	switch (protocolEnum)
	{
	case ProtRawRtp:
		protocolString = PROT_RAW_RTP;
		break;
	case ProtSip:
		protocolString = PROT_SIP;
		break;
	case ProtSkinny:
		protocolString = PROT_SKINNY;
		break;
	default:
		protocolString = PROT_UNKN;
	}
	return protocolString;
}

bool VoIpSession::OrkUidMatches(CStdString &oUid)
{
	if(m_orkUid.CompareNoCase(oUid) == 0)
	{
		return true;
	}

	return false;
}

bool VoIpSession::PartyMatches(CStdString &party)
{
	if(party.size() > 0)
	{
		if(m_localParty.CompareNoCase(party) == 0 || m_remoteParty.CompareNoCase(party) == 0)
		{
			return true;
		}
	}
	return false;
}

bool VoIpSession::NativeCallIdMatches(CStdString& callid)
{
	if(callid.size() > 0)
	{
		if(m_callId.CompareNoCase(callid) == 0)
		{
			return true;
		}
	}
	return false;
}

void VoIpSession::ReportSkinnyCallInfo(SkCallInfoStruct* callInfo, IpHeaderStruct* ipHeader)
{
}

void VoIpSession::ReportSkinnyCallStateMessage(SkCallStateMessageStruct* callStateMessage, IpHeaderStruct* ipHeader)
{
}

CStdString VoIpSession::GetOrkUid()
{
	return m_orkUid;
}

void VoIpSession::MarkAsOnDemand(CStdString& side)
{
	// Report direction
	m_onDemand = true;
	if(m_started == true)
	{
		CaptureEventRef event(new CaptureEvent());
		event->m_type = CaptureEvent::EtKeyValue;
		event->m_key  = CStdString("ondemand");
		event->m_value = CStdString("true");
		g_captureEventCallBack(event, m_capturePort);

		// Report audio keep direction
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtAudioKeepDirection;
		event->m_value = side;
		g_captureEventCallBack(event, m_capturePort);

		// Trigger metadata update
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtUpdate;
		g_captureEventCallBack(event, m_capturePort);
	}
}

void VoIpSession::MarkAsOnDemandOff()
{
	m_onDemand = false;
	if(m_started == true)
	{
		CaptureEventRef event(new CaptureEvent());
		event->m_type = CaptureEvent::EtKeyValue;
		event->m_key  = CStdString("ondemand");
		event->m_value = CStdString("false");
		g_captureEventCallBack(event, m_capturePort);

		// Trigger metadata update
		event.reset(new CaptureEvent());
		event->m_type = CaptureEvent::EtUpdate;
		g_captureEventCallBack(event, m_capturePort);
	}
}

void VoIpSession::SkinnyTrackConferencesTransfers(CStdString callId, CStdString capturePort)
{

}

bool VoIpSession::IsMatchedLocalOrRemoteIp(struct in_addr ip)
{
	if(ip.s_addr == m_localIp.s_addr || ip.s_addr == m_remoteIp.s_addr)
	{
		return true;
	}
	else
		return false;
}

//=====================================================================
VoIpSessions::VoIpSessions()
{
	m_log = Logger::getLogger("rtpsessions");
	if(CONFIG.m_debug)
	{
		m_alphaCounter.Reset();
	}
}


void VoIpSessions::ReportSipInvite(SipInviteInfoRef& invite)
{
}

void VoIpSessions::ReportSipSubscribe(SipSubscribeInfoRef& subscribe)
{

}

void VoIpSessions::ReportSipErrorPacket(SipFailureMessageInfoRef& info)
{
}

void VoIpSessions::ReportSipSessionProgress(SipSessionProgressInfoRef& info)
{
}

void VoIpSessions::ReportSip302MovedTemporarily(Sip302MovedTemporarilyInfoRef& info)
{
}

void VoIpSessions::ReportSip200Ok(Sip200OkInfoRef info)
{
}

void VoIpSessions::ReportSipBye(SipByeInfoRef& bye)
{
}


static inline bool isNotAlnum(char c) { return !isalnum(c); }

void VoIpSessions::ReportSipNotify(SipNotifyInfoRef& notify)
{
}

void VoIpSessions::ReportSipInfo(SipInfoRef& info)
{
}

void VoIpSessions::ReportSipRefer(SipReferRef& info)
{
}

void VoIpSessions::UpdateEndpointWithCallInfo(SkCallInfoStruct* callInfo, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

void VoIpSessions::UpdateSessionWithCallInfo(SkCallInfoStruct* callInfo, VoIpSessionRef& session)
{
	session->m_skinnyLineInstance = callInfo->lineInstance;
	CStdString lp;
	CStdString lpn;
	CStdString rp;
	CStdString logMsg;
	char szEndPointIp[16];

	VoIpEndpointInfoRef endpoint = GetVoIpEndpointInfo(session->m_endPointIp, session->m_endPointSignallingPort);
	inet_ntopV4(AF_INET, (void*)&session->m_endPointIp, szEndPointIp, sizeof(szEndPointIp));

	if (session->m_hasReceivedCallInfo==true &&  strcmp(callInfo->calledParty,callInfo->callingParty)==0) {
		return;
	}
	session->m_hasReceivedCallInfo = true;

	switch(callInfo->callType)
	{
	case SKINNY_CALL_TYPE_INBOUND:
		lp = callInfo->calledParty;
		lpn = callInfo->calledPartyName;
		rp = callInfo->callingParty;
		if(m_skinnyGlobalNumbersList.find(lp) == m_skinnyGlobalNumbersList.end())
		{
			session->m_localParty = GetLocalPartyMap(lp);
		}
		session->m_localPartyName = GetLocalPartyMap(lpn);
		if(rp.length() > 0)
		{
			session->m_remoteParty = GetLocalPartyMap(rp);
		}
		session->m_direction = CaptureEvent::DirIn;
		break;
	case SKINNY_CALL_TYPE_FORWARD:
		lp = callInfo->calledParty;
		lpn = callInfo->calledPartyName;
		rp = callInfo->callingParty;
		if(endpoint.get() && ((endpoint->m_extension).size() > 0))
		{
			if(m_skinnyGlobalNumbersList.find(lp) == m_skinnyGlobalNumbersList.end())
			{
				session->m_localParty = GetLocalPartyMap(endpoint->m_extension);
			}
			session->m_localEntryPoint = lp;
			logMsg.Format("[%s] callType is FORWARD: set localparty:%s (obtained from endpoint:%s)", session->m_trackingId, session->m_localParty, szEndPointIp);
			LOG4CXX_DEBUG(m_log, logMsg);
		}
		session->m_localPartyName = GetLocalPartyMap(lpn);
		if(rp.length() > 0)
		{
			session->m_remoteParty = GetLocalPartyMap(rp);
		}
		session->m_direction = CaptureEvent::DirIn;
		break;
	case SKINNY_CALL_TYPE_OUTBOUND:
		lp = callInfo->callingParty;
		lpn = callInfo->callingPartyName;
		rp = callInfo->calledParty;
		if(m_skinnyGlobalNumbersList.find(lp) == m_skinnyGlobalNumbersList.end())
		{
			session->m_localParty = GetLocalPartyMap(lp);
		}
		session->m_localPartyName = GetLocalPartyMap(lpn);
		if(rp.length() > 0)
		{
			session->m_remoteParty = GetLocalPartyMap(rp);
		}		
		session->m_direction = CaptureEvent::DirOut;
		break;
	default:
		lp = callInfo->calledParty;
		lpn = callInfo->calledPartyName;
		rp = callInfo->callingParty;
		if(m_skinnyGlobalNumbersList.find(lp) == m_skinnyGlobalNumbersList.end())
		{
			session->m_localParty = GetLocalPartyMap(lp);
		}
		session->m_localPartyName = GetLocalPartyMap(lpn);
		if(rp.length() > 0)
		{
			session->m_remoteParty = GetLocalPartyMap(rp);
		}		
	}
}

VoIpEndpointInfoRef VoIpSessions::GetVoIpEndpointInfoByIp(struct in_addr *ip)
{
	std::map<unsigned long long, VoIpEndpointInfoRef>::iterator pair;
	VoIpEndpointInfoRef endpoint;

	for(pair = m_endpoints.begin(); pair != m_endpoints.end(); pair++)
	{
		VoIpEndpointInfoRef ep = pair->second;

		if(ep.get() && (ep->m_ip.s_addr == ip->s_addr))
		{
			endpoint = ep;
			break;
		}
	}

	return endpoint;
}

bool VoIpSessions::SkinnyFindMostLikelySessionForRtp(RtpPacketInfoRef& rtpPacket, VoIpEndpointInfoRef& endpoint)
{
	return true;
}

bool VoIpSessions::SkinnyFindMostLikelySessionForRtpBehindNat(RtpPacketInfoRef& rtpPacket)
{
	return true;
}


void VoIpSession::ReportMetadataUpdateSkinny() {

}

void VoIpSessions::ReportSkinnyCallInfo(SkCallInfoStruct* callInfo, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{

}

void VoIpSessions::ReportSkinnyCallStateMessage(SkCallStateMessageStruct* callStateMessage, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

VoIpSessionRef VoIpSessions::findByMediaAddress(struct in_addr ipAddress, unsigned short udpPort)
{
	unsigned long long mediaAddress;
	Craft64bitMediaAddress(mediaAddress, ipAddress, udpPort);

	VoIpSessionRef session;
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	pair = m_byIpAndPort.find(mediaAddress);
	if (pair != m_byIpAndPort.end())
	{
		session = pair->second;
	}
	return session;
}


VoIpSessionRef VoIpSessions::findByEndpointIpUsingIpAndPort(struct in_addr endpointIpAddr)
{
	VoIpSessionRef session;
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;

	// Scan all sessions and try to find a session on the same IP endpoint
	// This function uses the m_byIpAndPort mapping unlike findByEndpointIp()

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end(); pair++)
	{
		VoIpSessionRef tmpSession = pair->second;

		if((unsigned int)tmpSession->m_endPointIp.s_addr == (unsigned int)endpointIpAddr.s_addr)
		{
			session = tmpSession;
			break;
		}
	}

	return session;
}

// Find a session by Skinny endpoint IP address. 
// If a passThruPartyId is supplied, only returns session matching both criteria
VoIpSessionRef VoIpSessions::findByEndpointIp(struct in_addr endpointIpAddr, int passThruPartyId)
{
	VoIpSessionRef session;
	std::map<CStdString, VoIpSessionRef>::iterator pair;

	// Scan all sessions and try to find a session on the same IP endpoint
	for(pair = m_byCallId.begin(); pair != m_byCallId.end(); pair++)
	{
		VoIpSessionRef tmpSession = pair->second;

		if((unsigned int)tmpSession->m_endPointIp.s_addr == (unsigned int)endpointIpAddr.s_addr)
		{
			if(passThruPartyId == 0 || tmpSession->m_skinnyPassThruPartyId == passThruPartyId)
			{
				session = tmpSession;
				break;
			}
		}
	}

	return session;
}

// Find session with newest RTP
VoIpSessionRef VoIpSessions::findNewestRtpByEndpointIp(struct in_addr endpointIpAddr)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	VoIpSessionRef session;
	RtpPacketInfoRef lastPacket;
	int latest = 0;

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end(); pair++)
	{
		VoIpSessionRef tmpSession = pair->second;

		if((unsigned int)tmpSession->m_endPointIp.s_addr == (unsigned int)endpointIpAddr.s_addr)
		{
			lastPacket = tmpSession->GetLastRtpPacket();
			if(lastPacket.get())
			{
				if(lastPacket->m_arrivalTimestamp > latest)
				{
					latest = lastPacket->m_arrivalTimestamp;
					session = tmpSession;
				}
			}
			else
			{
				session = tmpSession;
			}
		}
	}

	return session;
}

// Find a session by Skinny endpoint IP address and by Skinny Line ID
VoIpSessionRef VoIpSessions::findByEndpointIpAndLineInstance(struct in_addr endpointIpAddr, int lineInstance)
{
	VoIpSessionRef session;
	std::map<CStdString, VoIpSessionRef>::iterator pair;

	// Scan all sessions and try to find a session on the same IP endpoint
	for(pair = m_byCallId.begin(); pair != m_byCallId.end(); pair++)
	{
		VoIpSessionRef tmpSession = pair->second;

		if((unsigned int)tmpSession->m_endPointIp.s_addr == (unsigned int)endpointIpAddr.s_addr)
		{
			if(tmpSession->m_skinnyLineInstance == lineInstance)
			{
				session = tmpSession;
				break;
			}
		}
	}
	return session;
}

VoIpSessionRef VoIpSessions::SipfindNewestBySenderIp(struct in_addr receiverIpAddr)
{
	VoIpSessionRef session;
	std::map<CStdString, VoIpSessionRef>::iterator pair;

	// Scan all sessions and try to find the most recently signalled session on the IP endpoint
	// This always scans the entire session list, might be good to index sessions by endpoint at some point
	for(pair = m_byCallId.begin(); pair != m_byCallId.end(); pair++)
	{
		VoIpSessionRef tmpSession = pair->second;

		if((unsigned int)tmpSession->m_invite->m_senderIp.s_addr == (unsigned int)receiverIpAddr.s_addr)
		{
			if(session.get())
			{
				if(tmpSession->m_sipLastInvite.usec() > session->m_sipLastInvite.usec())
				{
					session = tmpSession;
				}
			}
			else
			{
				session = tmpSession;
			}
		}
	}

	return session;
}

VoIpSessionRef VoIpSessions::findNewestByEndpoint(struct in_addr endpointIpAddr, unsigned short endpointSignallingPort)
{
	VoIpSessionRef session;
	std::map<CStdString, VoIpSessionRef>::iterator pair;
	unsigned short sessionSignallingPort = 0;

	// Scan all sessions and try to find the most recently signalled session on the IP endpoint
	// This always scans the entire session list, might be good to index sessions by endpoint at some point
	for(pair = m_byCallId.begin(); pair != m_byCallId.end(); pair++)
	{
		VoIpSessionRef tmpSession = pair->second;

		if(DLLCONFIG.m_skinnyBehindNat)
		{
			sessionSignallingPort = tmpSession->m_endPointSignallingPort;
		}
		else
		{
			// Not behind NAT: make sure that we match on endpoint IP address only
			endpointSignallingPort = 0;
			sessionSignallingPort = 0;
		}

		if((unsigned int)tmpSession->m_endPointIp.s_addr == (unsigned int)endpointIpAddr.s_addr &&
			sessionSignallingPort == endpointSignallingPort )
		{
			if(session.get())
			{
				if(tmpSession->m_skinnyLastCallInfoTime.usec() > session->m_skinnyLastCallInfoTime.usec())
				{
					session = tmpSession;
				}
			}
			else
			{
				session = tmpSession;
			}
		}
	}

	return session;
}

//bool VoIpSessions::ChangeCallId(VoIpSessionRef& session, unsigned int newId)
//{
//	bool result = false;
//	if(newId)
//	{
//		CStdString newCallId = GenerateSkinnyCallId(session->m_endPointIp, newId);
//
//		std::map<CStdString, VoIpSessionRef>::iterator pair = m_byCallId.find(newCallId);
//		if (pair == m_byCallId.end())
//		{
//			// Ok, no session exists with the new Call ID, go ahead
//			result = true;
//			CStdString oldCallId = session->m_callId;
//			m_byCallId.erase(oldCallId);
//			session->m_callId = newCallId;
//			m_byCallId.insert(std::make_pair(newCallId, session));
//
//			if(m_log->isInfoEnabled())
//			{
//				CStdString logMsg;
//				logMsg.Format("[%s] callId %s becomes %s", session->m_trackingId, oldCallId, newCallId);
//				LOG4CXX_INFO(m_log, logMsg);
//			}
//		}
//		else
//		{
//			// a session already exists with the new Call ID, ignore
//		}
//	}
//	return result;
//}

/*
 * Deprecated, use Craft64bitMediaAddress instead
 * */
void VoIpSessions::CraftMediaAddress(CStdString& mediaAddress, struct in_addr ipAddress, unsigned short udpPort)
{
	char szIpAddress[16];

	if(DLLCONFIG.m_rtpTrackByUdpPortOnly == false)
	{
		inet_ntopV4(AF_INET, (void*)&ipAddress, szIpAddress, sizeof(szIpAddress));
		mediaAddress.Format("%s,%u", szIpAddress, udpPort);
	}
	else
	{
		mediaAddress.Format("%u", udpPort);
	}
}

void VoIpSessions::Craft64bitMediaAddress(unsigned long long& mediaAddress, struct in_addr ipAddress, unsigned short udpPort)
{
	if(DLLCONFIG.m_rtpTrackByUdpPortOnly == false)
	{
		mediaAddress = (((unsigned long long)ipAddress.s_addr) << 16) | udpPort;
	}
	else
	{
		mediaAddress = (unsigned long long)udpPort;
	}
}

CStdString VoIpSessions::MediaAddressToString(unsigned long long ipAndPort)
{
	CStdString strMediaAddress;

	if(DLLCONFIG.m_rtpTrackByUdpPortOnly == false)
	{
		char szIp[16];
		unsigned int ip;
		unsigned short port;
		ip = ipAndPort >> 16;
		port = ipAndPort & 0xffff;
		inet_ntopV4(AF_INET, (void*)&ip, szIp, sizeof(szIp));
		strMediaAddress.Format("%s,%u", szIp, port);
		return strMediaAddress;
	}
	else
	{
		strMediaAddress.Format("%u", ipAndPort);
		return strMediaAddress;
	}

}

void VoIpSessions::SetMediaAddress(VoIpSessionRef& session, struct in_addr mediaIp, unsigned short mediaPort)
{
	if(mediaPort == 0)
	{
		return;
	}
	if(DLLCONFIG.m_mediaAddressBlockedIpRanges.Matches(mediaIp))
	{
		char szMediaIp[16];
		CStdString logMsg;
		inet_ntopV4(AF_INET, (void*)&mediaIp, szMediaIp, sizeof(szMediaIp));

		logMsg.Format("[%s] %s,%d rejected by MediaAddressBlockedIpRanges", session->m_trackingId, szMediaIp, mediaPort);
		LOG4CXX_INFO(m_log, logMsg);

		return;
	}
	
	if(!DLLCONFIG.m_mediaAddressAllowedIpRanges.Empty())
	{
		if(DLLCONFIG.m_mediaAddressAllowedIpRanges.Matches(mediaIp) == false)
		{
			char szMediaIp[16];
			CStdString logMsg;
			inet_ntopV4(AF_INET, (void*)&mediaIp, szMediaIp, sizeof(szMediaIp));

			logMsg.Format("[%s] %s,%d is not allowed by MediaAddressAllowedIpRanges", session->m_trackingId, szMediaIp, mediaPort);
			LOG4CXX_INFO(m_log, logMsg);
			return;
		}
	}

	CStdString logMsg;

	unsigned long long mediaAddress;
	Craft64bitMediaAddress(mediaAddress, mediaIp, mediaPort);

	bool doChangeMediaAddress = true;

	VoIpSessionRef oldSession = findByMediaAddress(mediaIp, mediaPort);
	if(oldSession.get())
	{
		// A session exists on the same IP+port

		if(oldSession->m_trackingId.Equals(session->m_trackingId))
		{
			// Old and new are the same session, do nothing
			doChangeMediaAddress = false;
		}
		else if(oldSession->m_protocol == VoIpSession::ProtRawRtp || oldSession->m_numRtpPackets == 0 ||
			(session->m_protocol == VoIpSession::ProtSkinny && DLLCONFIG.m_skinnyAllowMediaAddressTransfer)
			|| (session->m_protocol == VoIpSession::ProtSip && DLLCONFIG.m_sipAllowMediaAddressTransfer))
		{
			logMsg.Format("[%s] on %s replaces [%s]",
							session->m_trackingId, MediaAddressToString(mediaAddress), oldSession->m_trackingId);
			LOG4CXX_INFO(m_log, logMsg);
			if(oldSession->m_protocol == VoIpSession::ProtRawRtp)
			{
				// Pure RTP session: stop it now or it will never be hoovered.
				// (Do not stop signalled sessions, better let them timeout and be hoovered. Useful for skinny internal calls where media address back and forth must not kill sessions with the best metadata.)
				Stop(oldSession);
			}
			else
			{
				// Signalled session, just remove them from the media address map so we make room for the new mapping
				RemoveFromMediaAddressMap(oldSession, mediaAddress);
			}
		}
		else
		{
			doChangeMediaAddress = false;
			logMsg.Format("[%s] on %s will not replace [%s]",
							session->m_trackingId, MediaAddressToString(mediaAddress), oldSession->m_trackingId);
			LOG4CXX_INFO(m_log, logMsg);
		}
	}
	if(doChangeMediaAddress)
	{
		if(m_log->isInfoEnabled())
		{
			char szEndPointIp[16];
			inet_ntopV4(AF_INET, (void*)&session->m_endPointIp, szEndPointIp, sizeof(szEndPointIp));
			logMsg.Format("[%s] media address:%s %s callId:%s endpoint:%s", session->m_trackingId, MediaAddressToString(mediaAddress), VoIpSession::ProtocolToString(session->m_protocol),session->m_callId, szEndPointIp);
			LOG4CXX_INFO(m_log, logMsg);
		}

		if (DLLCONFIG.m_rtpAllowMultipleMappings == false)
		{
			RemoveFromMediaAddressMap(session, session->m_ipAndPort);	// remove old mapping of the new session before remapping
			session->m_mediaAddresses.clear();
			//m_byIpAndPort.erase(session->m_ipAndPort);
		}
		session->m_mediaAddresses.push_back(mediaAddress);
		session->m_ipAndPort = mediaAddress;
		session->m_rtpIp = mediaIp;
		m_byIpAndPort.insert(std::make_pair(session->m_ipAndPort, session));	// insert new mapping

		CStdString numSessions = IntToString(m_byIpAndPort.size());
		LOG4CXX_DEBUG(m_log, CStdString("ByIpAndPort: ") + numSessions);
	}
}

void VoIpSessions::RemoveFromMediaAddressMap(VoIpSessionRef& session, unsigned long long& mediaAddress)
{
	if(mediaAddress == 0)
	{
		return;
	}

	// Defensively check if the session referenced in the media address map actually is the same session
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	pair = m_byIpAndPort.find(mediaAddress);
	if (pair != m_byIpAndPort.end())
	{
		VoIpSessionRef sessionOnMap = pair->second;
		if(sessionOnMap.get() == session.get())
		{
			// They are the same session, all good
			m_byIpAndPort.erase(mediaAddress);
			CStdString numSessions = IntToString(m_byIpAndPort.size());
			LOG4CXX_DEBUG(m_log, CStdString("ByIpAndPort: ") + numSessions);
		}
		else
		{
			CStdString sessionOnMapTrackingId;
			if(sessionOnMap.get())
			{
				sessionOnMapTrackingId = sessionOnMap->m_trackingId;
			}
			else
			{
				sessionOnMapTrackingId = "null";
			}
			CStdString logString;
			logString.Format("rtp:%s belongs to [%s] not to [%s]", MediaAddressToString(mediaAddress), sessionOnMapTrackingId, session->m_trackingId);
			LOG4CXX_INFO(m_log, logString);
		}
	}
}


CStdString VoIpSessions::GenerateSkinnyCallId(struct in_addr endpointIp, unsigned short endpointSkinnyPort, unsigned int callId)
{
}

void VoIpSessions::ReportSkinnyOpenReceiveChannelAck(SkOpenReceiveChannelAckStruct* openReceive, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}


void VoIpSessions::ReportSkinnyStartMediaTransmission(SkStartMediaTransmissionStruct* startMedia, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

void VoIpSessions::ReportSkinnyStopMediaTransmission(SkStopMediaTransmissionStruct* stopMedia, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

void VoIpSessions::SetEndpointExtension(CStdString& extension, struct in_addr* endpointIp, CStdString& callId, unsigned short skinnyPort)
{
	std::map<unsigned long long, VoIpEndpointInfoRef>::iterator pair;
	VoIpEndpointInfoRef endpoint;
	char szEndpointIp[16];
	unsigned long long ipAndPort;

	inet_ntopV4(AF_INET, (void*)endpointIp, szEndpointIp, sizeof(szEndpointIp));
	Craft64bitMediaAddress(ipAndPort, *endpointIp, skinnyPort);

	pair = m_endpoints.find(ipAndPort);
	if(pair != m_endpoints.end())
	{
		// Update the existing endpoint	info
		endpoint = pair->second;
		endpoint->m_extension = extension;
		if(callId.size())
		{
			endpoint->m_latestCallId = callId;
		}
	}
	else
	{
		// Create endpoint info for the new endpoint
		CStdString logMsg;

		endpoint.reset(new VoIpEndpointInfo());
		endpoint->m_extension = extension;
		endpoint->m_skinnyPort = skinnyPort;

		memcpy(&endpoint->m_ip, endpointIp, sizeof(endpoint->m_ip));
		if(callId.size())
		{
			endpoint->m_latestCallId = callId;
		}
		m_endpoints.insert(std::make_pair(ipAndPort, endpoint));
		logMsg.Format("New endpoint created:%s callId:%s map:%s", endpoint->m_extension, endpoint->m_latestCallId, MediaAddressToString(ipAndPort));
		LOG4CXX_DEBUG(m_log, logMsg);
	}
	if(endpoint.get())
	{
		CStdString logMsg;

		logMsg.Format("Extension:%s callId:%s is on endpoint:%s", endpoint->m_extension, endpoint->m_latestCallId, szEndpointIp);
		LOG4CXX_INFO(m_log, logMsg);
	}
}

void VoIpSessions::ReportSkinnyLineStat(SkLineStatStruct* lineStat, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

void VoIpSessions::ReportSkinnySoftKeyHold(SkSoftKeyEventMessageStruct* skEvent, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

void VoIpSessions::ReportSkinnySoftKeyResume(SkSoftKeyEventMessageStruct* skEvent, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}
void VoIpSessions::ReportSkinnySoftKeyConfPressed(struct in_addr endpointIp, TcpHeaderStruct* tcpHeader)
{
}
void VoIpSessions::ReportSkinnySoftKeySetConfConnected(struct in_addr endpointIp, TcpHeaderStruct* tcpHeader)
{
}

void VoIpSessions::ReportSkinnySoftKeySetTransfConnected(SkSoftKeySetDescriptionStruct* skEvent, IpHeaderStruct* ipHeader, TcpHeaderStruct* tcpHeader)
{
}

VoIpEndpointInfoRef VoIpSessions::GetVoIpEndpointInfo(struct in_addr endpointIp, unsigned short skinnyPort)
{
	char szEndpointIp[16];
	unsigned long long ipAndPort;
	std::map<unsigned long long, VoIpEndpointInfoRef>::iterator pair;

	inet_ntopV4(AF_INET, (void*)&endpointIp, szEndpointIp, sizeof(szEndpointIp));
	Craft64bitMediaAddress(ipAndPort, endpointIp, skinnyPort);

	pair = m_endpoints.find(ipAndPort);
	if(pair != m_endpoints.end())
	{
		return pair->second;
	}

	return VoIpEndpointInfoRef();
}


void VoIpSessions::Stop(VoIpSessionRef& session)
{
	TaggingSipTransferCalls(session);
	session->Stop();

	if(session->m_callId.size() > 0)
	{
		m_byCallId.erase(session->m_callId);
	}

	std::list<unsigned long long>::iterator it;
	for(it = session->m_mediaAddresses.begin(); it != session->m_mediaAddresses.end(); it++)
	{
		unsigned long long mediaAddress = *it;
		RemoveFromMediaAddressMap(session, mediaAddress);
	}
	session->m_mediaAddresses.clear();
}

bool VoIpSessions::ReportRtcpSrcDescription(RtcpSrcDescriptionPacketInfoRef& rtcpInfo)
{
	VoIpSessionRef session;

	session = findByMediaAddress(rtcpInfo->m_sourceIp, rtcpInfo->m_sourcePort - 1);
	if(session.get() != NULL)
	{
		session->ReportRtcpSrcDescription(rtcpInfo);
		return true;
	}

	session = findByMediaAddress(rtcpInfo->m_destIp, rtcpInfo->m_destPort - 1);
	if(session.get() != NULL)
	{
		session->ReportRtcpSrcDescription(rtcpInfo);
		return true;
	}

	return false;
}


void VoIpSessions::ReportRtpPacket(RtpPacketInfoRef& rtpPacket)
{
	int numSessionsFound = 0;
	VoIpSessionRef session1;
	VoIpSessionRef session2;
	VoIpSessionRef session;
	CStdString logMsg;

	int sourcePort = rtpPacket->m_sourcePort;
	int destPort = rtpPacket->m_destPort;
	bool sourceAddressIsTracked = false;
        //kexin
        char* strIp = inet_ntoa(*((struct in_addr*)&(rtpPacket->m_destIp)));

        std::map<CStdString, CStdString>::iterator it = DLLCONFIG.ip_exts.find(strIp);
        if (it == DLLCONFIG.ip_exts.end()) {
          return;
        }
        else {
          rtpPacket->ip = strIp;
          rtpPacket->ext = it->second;
        }
	// Does a session exist with this destination Ip+Port
	session2 = findByMediaAddress(rtpPacket->m_destIp, destPort);
	if (session2.get() != NULL)
	{
		// Found a session give it the RTP packet info
		session = session2;
		if(session2->AddRtpPacket(rtpPacket))
		{
			numSessionsFound++;
		}
		else
		{
			// RTP discontinuity detected
			Stop(session2);
		}
	}


	if(numSessionsFound == 0)
	{
		// create new Raw RTP session and insert into IP+Port map
		CStdString trackingId = m_alphaCounter.GetNext();
                trackingId += "_";
                trackingId += strIp;
                
                CStdString strPort;
                strPort.Format("%d", destPort); 
                trackingId += "_";
                trackingId += strPort;

		VoIpSessionRef session(new VoIpSession(trackingId));
		session->m_protocol = VoIpSession::ProtRawRtp;
                CStdString logMsg;
                logMsg.Format(" @@@-1  Create new raw session %s",trackingId);
                LOG4CXX_INFO(m_log, logMsg);
		// Make sure the session is tracked by the right IP address
		struct in_addr rtpIp;
		unsigned short rtpPort;
	        rtpIp = rtpPacket->m_destIp;
		rtpPort = rtpPacket->m_destPort;
                //
		session->m_endPointIp = rtpIp;
                session->ip = strIp;
                session->ext = it->second;
		SetMediaAddress(session, rtpIp, rtpPort);
		session->AddRtpPacket(rtpPacket);
		CStdString numSessions = IntToString(m_byIpAndPort.size());
		LOG4CXX_DEBUG(m_log, CStdString("ByIpAndPort: ") + numSessions);
		CStdString rtpString;
		rtpPacket->ToString(rtpString);
		LOG4CXX_INFO(m_log, "[" + trackingId + "] created by RTP packet " + rtpString);
	}
}

void VoIpSessions::TrySessionCallPickUp(CStdString replacesCallId, bool& result)
{
}


void VoIpSessions::UnEscapeUrl(CStdString& in, CStdString& out)
{
	// Translates all %xx escaped sequences to corresponding ascii characters
	out = "";
	char pchHex[3];
	for (unsigned int i = 0; i<in.size(); i++)
	{
		switch (in.GetAt(i))
		{
			case '+':
				out += ' ';
				break;
			case '%':
				if (in.GetAt(++i) == '%')
				{
					out += '%';
					break;
				}
				pchHex[0] = in.GetAt(i);
				pchHex[1] = in.GetAt(++i);
				pchHex[2] = 0;
				out += (char)strtol(pchHex, NULL, 16);
				break;
			default:
				out += in.GetAt(i);
		}
	}
}

void VoIpSessions::UrlExtraction(CStdString& input, struct in_addr* endpointIp)
{
	// read string and extract values into map
	UrlState state = VoIpSessions::UrlStartState;
	CStdString key;
	CStdString value;
	CStdString errorDescription;

	input.Trim();

	for(unsigned int i=0; i<input.length() && state!= VoIpSessions::UrlErrorState; i++)
	{
		TCHAR character = input[i];

		switch(state)
		{
		case VoIpSessions::UrlStartState:
			if(character == '&')
			{
				;	// ignore ampersands
			}
			else if(isalnum(character) )
			{
				state = VoIpSessions::UrlKeyState;
				key = character;
			}
			else
			{
				state = VoIpSessions::UrlErrorState;
				errorDescription = "Cannot find key start, keys must be alphanum";
			}
			break;
		case VoIpSessions::UrlKeyState:
			if(isalnum(character) )
			{
				key += character;
			}
			else if (character == '=')
			{
				state = VoIpSessions::UrlValueState;
				value.Empty();
			}
			else
			{
				state = VoIpSessions::UrlErrorState;
				errorDescription = "Invalid key character, keys must be alphanum";
			}
			break;
		case VoIpSessions::UrlValueState:
			if( character == '=')
			{
				state = VoIpSessions::UrlErrorState;
				errorDescription = "Value followed by = sign, value should always be followed by space sign";
			}
			else if (character == '&')
			{
				state = VoIpSessions::UrlStartState;
			}
			else
			{
				value += character;
			}
			break;
		default:
			state = VoIpSessions::UrlErrorState;
			errorDescription = "Non-existing state";
		}	// switch(state)

		if ( (state == VoIpSessions::UrlStartState) || (i == (input.length()-1)) )
		{
			if (!key.IsEmpty())
			{
				// Url unescape
				CStdString unescapedValue;
				UnEscapeUrl(value, unescapedValue);

				std::map<unsigned long long, VoIpEndpointInfoRef>::iterator pair;
				VoIpEndpointInfoRef endpoint;
				unsigned long long ipAndPort;

				Craft64bitMediaAddress(ipAndPort, *endpointIp, 0);

				pair = m_endpoints.find(ipAndPort);
				if(pair != m_endpoints.end())
				{
					endpoint = pair->second;
					std::map<CStdString, UrlExtractionValueRef>::iterator it;
					it = endpoint->m_urlExtractionMap.find(key);
					if(it != endpoint->m_urlExtractionMap.end())
					{
						it->second->m_value = unescapedValue;
						it->second->m_timestamp = time(NULL);
					}
					else
					{
						UrlExtractionValueRef urlExtractionValue(new UrlExtractionValue(unescapedValue));
						endpoint->m_urlExtractionMap.insert(std::make_pair(key, urlExtractionValue));
					}
				}
				else
				{
					UrlExtractionValueRef urlExtractionValue(new UrlExtractionValue(unescapedValue));
					endpoint.reset(new VoIpEndpointInfo);
					memcpy(&endpoint->m_ip, endpointIp, sizeof(endpoint->m_ip));
					endpoint->m_urlExtractionMap.insert(std::make_pair(key, urlExtractionValue));
					m_endpoints.insert(std::make_pair(ipAndPort, endpoint));

				}

				key.Empty();
				value.Empty();
			}
		}
	}

}

void VoIpSessions::ReportOnDemandMarkerByIp(struct in_addr endpointIp)
{
	VoIpSessionRef session, chosenSession;
	std::list<VoIpSessionRef> sessionsOnIp;
	std::map<unsigned long long, VoIpSessionRef>::iterator it;
	for(it = m_byIpAndPort.begin(); it != m_byIpAndPort.end(); it++)
	{
		session = it->second;
		if(session.get() != NULL)
		{
			if(session->IsMatchedLocalOrRemoteIp(endpointIp) == true && session->m_numRtpPackets > 0)
			{
				sessionsOnIp.push_back(session);
			}
		}
	}

	std::list<VoIpSessionRef>::iterator it2;
	time_t latestRtp = 0;
	for(it2 = sessionsOnIp.begin(); it2 != sessionsOnIp.end(); it2++)
	{
		session = (*it2);
		if(session.get() != NULL)
		{
			if(session->m_lastUpdated > latestRtp)
			{
				latestRtp = session->m_lastUpdated;
				chosenSession = session;
			}
		}
	}
	if(chosenSession.get() != NULL)
	{
		chosenSession->m_keepRtp = true;
		CStdString side = "both";
		chosenSession->MarkAsOnDemand(side);
	}

}

void VoIpSessions::TaggingSipTransferCalls(VoIpSessionRef& session)
{
}

void VoIpSessions::CopyMetadataToNewSession(VoIpSessionRef& oldSession, VoIpSessionRef& newSession)
{
	if(oldSession.get() == NULL)
	{
		return;
	}
	newSession->m_ipAndPort = oldSession->m_ipAndPort;
	newSession->m_rtpIp = oldSession->m_rtpIp;
	newSession->m_callId = oldSession->m_callId;
	newSession->m_invite = oldSession->m_invite;
	newSession->m_protocol = oldSession->m_protocol;
	newSession->m_remotePartyNecSip = oldSession->m_remotePartyNecSip;
	newSession->m_localParty = oldSession->m_localParty;
	newSession->m_remoteParty = oldSession->m_remoteParty;
	newSession->m_localEntryPoint = oldSession->m_localEntryPoint;
	newSession->m_localPartyName = oldSession->m_localPartyName;
	newSession->m_remotePartyName = oldSession->m_remotePartyName;
	newSession->m_localPartyReported = oldSession->m_localPartyReported;
	newSession->m_remotePartyReported = oldSession->m_remotePartyReported;
	newSession->m_rtcpLocalParty = oldSession->m_rtcpLocalParty;
	newSession->m_rtcpRemoteParty = oldSession->m_rtcpRemoteParty;
	newSession->m_direction = oldSession->m_direction;
	newSession->m_localSide = oldSession->m_localSide;
	newSession->m_endPointIp = oldSession->m_endPointIp;
	newSession->m_endPointSignallingPort = oldSession->m_endPointSignallingPort;
	newSession->m_skinnyPassThruPartyId = oldSession->m_skinnyPassThruPartyId;
	newSession->m_sipLastInvite = oldSession->m_sipLastInvite;
	newSession->m_skinnyLastCallInfoTime = oldSession->m_skinnyLastCallInfoTime;
	newSession->m_skinnyLineInstance = oldSession->m_skinnyLineInstance;
	newSession->m_mediaAddresses = oldSession->m_mediaAddresses;
	newSession->m_sipDialedNumber = oldSession->m_sipDialedNumber;
	newSession->m_sipRemoteParty = oldSession->m_sipRemoteParty;
	newSession->m_isCallPickUp = oldSession->m_isCallPickUp;
	newSession->m_ssrcCandidate = oldSession->m_ssrcCandidate;

	newSession->m_metadataProcessed = true;
}

void VoIpSessions::ClearLocalPartyMap()
{
       m_localPartyMap.clear();
}

void VoIpSessions::StopAll()
{
        CStdString logMsg;
        logMsg.Format("Stop All Sessions");
        LOG4CXX_INFO(m_log, logMsg);
	time_t forceExpiryTime = time(NULL) + 2*DLLCONFIG.m_rtpSessionOnHoldTimeOutSec;
	Hoover(forceExpiryTime);
}

void VoIpSessions::Hoover(time_t now)
{
        CStdString logMsg;
        logMsg.Format(" voip session hoover");
        LOG4CXX_DEBUG(m_log, logMsg);
	CStdString numSessions = IntToString(m_byIpAndPort.size());
	LOG4CXX_DEBUG(m_log, "Hoover - check " + numSessions + " sessions time:" + IntToString(now));

	// Go round the ipAndPort session index and find inactive sessions
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	std::map<CStdString, VoIpSessionRef>::iterator pair2;
	std::list<VoIpSessionRef> toDismiss;

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end(); pair++)
	{
		VoIpSessionRef session = pair->second;
		int timeoutSeconds = 0;
		if(session->m_protocol == VoIpSession::ProtRawRtp)
		{
			timeoutSeconds = DLLCONFIG.m_rtpSessionTimeoutSec;
		}
		else
		{
			if(session->m_onHold)
			{
				timeoutSeconds = DLLCONFIG.m_rtpSessionOnHoldTimeOutSec;
			}
			else
			{
				if(session->m_numRtpPackets)
				{
					timeoutSeconds = DLLCONFIG.m_rtpSessionWithSignallingTimeoutSec;
				}
				else
				{
					timeoutSeconds = DLLCONFIG.m_rtpSessionWithSignallingInitialTimeoutSec;
				}
			}
		}
		if((now - session->m_lastUpdated) > timeoutSeconds)
		{
			toDismiss.push_back(session);
		}
	}

	// discard inactive sessions
	for (std::list<VoIpSessionRef>::iterator it = toDismiss.begin(); it != toDismiss.end() ; it++)
	{
		VoIpSessionRef session = *it;
		CStdString logMsg;
		logMsg.Format("[%s] %s Expired (RTP) ts:%u", session->m_trackingId, MediaAddressToString(session->m_ipAndPort), session->m_lastUpdated);
		LOG4CXX_INFO(m_log, logMsg);
		Stop(session);
	}

	// Go round the callId session index and find inactive sessions
	toDismiss.clear();
	for(pair2 = m_byCallId.begin(); pair2 != m_byCallId.end(); pair2++)
	{
		VoIpSessionRef session = pair2->second;

		if(session->m_onHold)
		{
			if((now - session->m_lastUpdated) > DLLCONFIG.m_rtpSessionOnHoldTimeOutSec)
			{
				toDismiss.push_back(session);
			}
		}
		else
		{
			if(session->m_numRtpPackets)
			{
				if((now - session->m_lastUpdated) > DLLCONFIG.m_rtpSessionWithSignallingTimeoutSec)
				{
					toDismiss.push_back(session);
				}
			}
			else
			{
				if((now - session->m_lastUpdated) > DLLCONFIG.m_rtpSessionWithSignallingInitialTimeoutSec)
				{
					toDismiss.push_back(session);
				}
			}
		}
	}

	// discard inactive sessions
	for (std::list<VoIpSessionRef>::iterator it2 = toDismiss.begin(); it2 != toDismiss.end() ; it2++)
	{
		VoIpSessionRef session = *it2;
		CStdString logMsg;
		logMsg.Format("[%s] %s Expired (CallID) ts:%u", session->m_trackingId, MediaAddressToString(session->m_ipAndPort), session->m_lastUpdated);
		Stop(session);
	}
}

void VoIpSessions::StartCaptureOrkuid(CStdString& orkuid, CStdString& side)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if(session->OrkUidMatches(orkuid))
		{
			session->m_keepRtp = true;
			found = true;
		}
	}

	if(found)
	{
		if((CaptureEvent::AudioKeepDirectionEnum)CaptureEvent::AudioKeepDirectionToEnum(side) == CaptureEvent::AudioKeepDirectionInvalid)
		{
			LOG4CXX_WARN(m_log, "[" + session->m_trackingId + "] invalid side:" + side);
		}

		session->MarkAsOnDemand(side);

		logMsg.Format("[%s] StartCaptureOrkuid: Started capture, orkuid:%s side:%s(%d)", session->m_trackingId, orkuid, side, CaptureEvent::AudioKeepDirectionToEnum(side));
	}
	else
	{
		logMsg.Format("StartCaptureOrkuid: No session has orkuid:%s side:%s", orkuid, side);
	}

	LOG4CXX_INFO(m_log, logMsg);
}

CStdString VoIpSessions::StartCaptureNativeCallId(CStdString& nativecallid, CStdString& side)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;
	CStdString orkUid = CStdString("");

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if(session->NativeCallIdMatches(nativecallid))
		{
			session->m_keepRtp = true;
			found = true;
			orkUid = session->GetOrkUid();
		}
	}

	if(found)
	{
		if((CaptureEvent::AudioKeepDirectionEnum)CaptureEvent::AudioKeepDirectionToEnum(side) == CaptureEvent::AudioKeepDirectionInvalid)
		{
			LOG4CXX_WARN(m_log, "[" + session->m_trackingId + "] invalid side:" + side);
		}

		session->MarkAsOnDemand(side);

		logMsg.Format("[%s] StartCaptureNativeCallId: Started capture, nativecallid:%s side:%s(%d)", session->m_trackingId, nativecallid, side, CaptureEvent::AudioKeepDirectionToEnum(side));
	}
	else
	{
		logMsg.Format("StartCaptureNativeCallId: No session has native callid:%s side:%s", nativecallid, side);
	}

	LOG4CXX_INFO(m_log, logMsg);

	return orkUid;
}

CStdString VoIpSessions::StartCapture(CStdString& party, CStdString& side)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;
	CStdString orkUid = CStdString("");

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if (session->PartyMatches(party))
		{
			session->m_keepRtp = true;
			found = true;
			orkUid = session->GetOrkUid();
		}
	}

	if(found)
	{
		if((CaptureEvent::AudioKeepDirectionEnum)CaptureEvent::AudioKeepDirectionToEnum(side) == CaptureEvent::AudioKeepDirectionInvalid)
		{
			LOG4CXX_WARN(m_log, "[" + session->m_trackingId + "] invalid side:" + side);
		}

		session->MarkAsOnDemand(side);

		logMsg.Format("[%s] StartCapture: Started capture, party:%s side:%s(%d)", session->m_trackingId, party, side, CaptureEvent::AudioKeepDirectionToEnum(side));
	}	
	else
	{
		logMsg.Format("StartCapture: No session has party %s side:%s", party, side);
	}
	
	LOG4CXX_INFO(m_log, logMsg);

	return orkUid;
}

CStdString VoIpSessions::PauseCapture(CStdString& party)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;
	CStdString orkUid = CStdString("");

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if (session->PartyMatches(party))
		{
			session->m_keepRtp = false;
			found = true;
			orkUid = session->GetOrkUid();
		}
	}

	if(found)
	{
		logMsg.Format("[%s] PauseCapture: Paused capture, party:%s", session->m_trackingId, party);
	}	
	else
	{
		logMsg.Format("PauseCapture: No session has party %s", party);
	}
	
	LOG4CXX_INFO(m_log, logMsg);

	return orkUid;
}

void VoIpSessions::PauseCaptureOrkuid(CStdString& orkuid)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if(session->OrkUidMatches(orkuid))
		{
			session->m_keepRtp = false;
			found = true;
		}
	}

	if(found)
	{
		logMsg.Format("[%s] PauseCaptureOrkuid: Paused capture, orkuid:%s", session->m_trackingId, orkuid);
	}
	else
	{
		logMsg.Format("PauseCaptureOrkuid: No session has orkuid:%s", orkuid);
	}

	LOG4CXX_INFO(m_log, logMsg);
}

CStdString VoIpSessions::PauseCaptureNativeCallId(CStdString& nativecallid)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;
	CStdString orkUid = CStdString("");

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if(session->NativeCallIdMatches(nativecallid))
		{
			session->m_keepRtp = false;
			found = true;
			orkUid = session->GetOrkUid();
		}
	}

	if(found)
	{
		logMsg.Format("[%s] PauseCaptureNativeCallId: Paused capture, nativecallid:%s", session->m_trackingId, nativecallid);
	}
	else
	{
		logMsg.Format("PauseCaptureNativeCallId: No session has native callid:%s", nativecallid);
	}

	LOG4CXX_INFO(m_log, logMsg);

	return orkUid;
}

CStdString VoIpSessions::StopCapture(CStdString& party, CStdString& qos)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;
	CStdString orkUid = CStdString("");

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if (session->PartyMatches(party))
		{
			found = true;
			orkUid = session->GetOrkUid();
		}
	}

	if(found)
	{
		logMsg.Format("[%s] StopCapture: stopping capture, party:%s", session->m_trackingId, party);
		LOG4CXX_INFO(m_log, logMsg);

		// This session might be stopped prematurely by this API call, preserve its metadata into a new session which will gather the subsequent RTP packets
		CStdString nextTrackId = m_alphaCounter.GetNext();
		VoIpSessionRef newSession(new VoIpSession(nextTrackId));
		CopyMetadataToNewSession(session, newSession);

		Stop(session);
		qos.Format("RtpNumPkts:%d RtpNumMissingPkts:%d RtpNumSeqGaps:%d RtpMaxSeqGap:%d", session->m_numRtpPackets, session->m_rtpNumMissingPkts, session->m_rtpNumSeqGaps, session->m_highestRtpSeqNumDelta);

		m_byIpAndPort.insert(std::make_pair(newSession->m_ipAndPort, newSession));
		m_byCallId.insert(std::make_pair(newSession->m_callId, newSession));
	}	
	else
	{
		logMsg.Format("StopCapture: No session has party %s", party);
		LOG4CXX_INFO(m_log, logMsg);
	}

	return orkUid;
}

void VoIpSessions::StopCaptureOrkuid(CStdString& orkuid, CStdString& qos)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if(session->OrkUidMatches(orkuid))
		{
			found = true;
		}
	}

	if(found)
	{
		logMsg.Format("[%s] StopCaptureOrkuid: stopping capture, orkuid:%s", session->m_trackingId, orkuid);
		LOG4CXX_INFO(m_log, logMsg);

		// This session might be stopped prematurely by this API call, preserve its metadata into a new session which will gather the subsequent RTP packets
		CStdString nextTrackId = m_alphaCounter.GetNext();
		VoIpSessionRef newSession(new VoIpSession(nextTrackId));
		CopyMetadataToNewSession(session, newSession);

		Stop(session);
		qos.Format("RtpNumPkts:%d RtpNumMissingPkts:%d RtpNumSeqGaps:%d RtpMaxSeqGap:%d", session->m_numRtpPackets, session->m_rtpNumMissingPkts, session->m_rtpNumSeqGaps, session->m_highestRtpSeqNumDelta);

		m_byIpAndPort.insert(std::make_pair(newSession->m_ipAndPort, newSession));
		m_byCallId.insert(std::make_pair(newSession->m_callId, newSession));
	}
	else
	{
		logMsg.Format("StopCaptureOrkuid: No session has orkuid:%s", orkuid);
		LOG4CXX_INFO(m_log, logMsg);
	}
}

CStdString VoIpSessions::StopCaptureNativeCallId(CStdString& nativecallid, CStdString& qos)
{
	std::map<unsigned long long, VoIpSessionRef>::iterator pair;
	bool found = false;
	CStdString logMsg;
	VoIpSessionRef session;
	CStdString orkUid = CStdString("");

	for(pair = m_byIpAndPort.begin(); pair != m_byIpAndPort.end() && found == false; pair++)
	{
		session = pair->second;

		if(session->NativeCallIdMatches(nativecallid))
		{
			found = true;
			orkUid = session->GetOrkUid();
		}
	}

	if(found)
	{
		logMsg.Format("[%s] StopCaptureNativeCallId: stopping capture, nativecallid:%s", session->m_trackingId, nativecallid);
		LOG4CXX_INFO(m_log, logMsg);

		// This session might be stopped prematurely by this API call, preserve its metadata into a new session which will gather the subsequent RTP packets
		CStdString nextTrackId = m_alphaCounter.GetNext();
		VoIpSessionRef newSession(new VoIpSession(nextTrackId));
		CopyMetadataToNewSession(session, newSession);

		Stop(session);
		qos.Format("RtpNumPkts:%d RtpNumMissingPkts:%d RtpNumSeqGaps:%d RtpMaxSeqGap:%d", session->m_numRtpPackets, session->m_rtpNumMissingPkts, session->m_rtpNumSeqGaps, session->m_highestRtpSeqNumDelta);

		m_byIpAndPort.insert(std::make_pair(newSession->m_ipAndPort, newSession));
		m_byCallId.insert(std::make_pair(newSession->m_callId, newSession));
	}
	else
	{
		logMsg.Format("StopCaptureNativeCallId: No session has native callid:%s", nativecallid);
		LOG4CXX_INFO(m_log, logMsg);
	}

	return orkUid;
}

void VoIpSessions::SaveLocalPartyMap(CStdString& oldparty, CStdString& newparty)
{
	m_localPartyMap.insert(std::make_pair(oldparty, newparty));
	LOG4CXX_DEBUG(m_log, "Saved map oldparty:" + oldparty + " newparty:" + newparty);
}

CStdString VoIpSessions::GetLocalPartyMap(CStdString& oldlocalparty)
{
	CStdString newlocalparty;
	std::map<CStdString, CStdString>::iterator pair;

	newlocalparty = oldlocalparty;

	pair = m_localPartyMap.find(oldlocalparty);
	if(pair != m_localPartyMap.end())
	{
		newlocalparty = pair->second;
		LOG4CXX_DEBUG(m_log, "Mapped oldparty:" + oldlocalparty + " to newparty:" + newlocalparty);
	}

	return newlocalparty;
}

void VoIpSessions::SaveSkinnyGlobalNumbersList(CStdString& number)
{
	m_skinnyGlobalNumbersList.insert(std::make_pair(number, 0));
	LOG4CXX_DEBUG(m_log, "Saved skinny global number:" + number);
}

void VoIpSession::TriggerOnDemandViaDtmf() {
	m_keepRtp = true;
	CStdString side = "both";
	MarkAsOnDemand(side);
}

//============================================================
UrlExtractionValue::UrlExtractionValue()
{
	m_timestamp = time(NULL);
}

UrlExtractionValue::UrlExtractionValue(CStdString value)
{
	m_value = value;
	m_timestamp = time(NULL);
}

//================================================

VoIpEndpointInfo::VoIpEndpointInfo()
{
	m_lastConferencePressed = 0;
	m_lastConnectedWithConference = 0;
	m_origOrkUid = "";
}
