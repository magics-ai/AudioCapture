#ifndef _ASR_PORTAL_
#define _ASR_PORTAL_

#include "asr_bd/audio_streaming_client.h"
#include "asr_bd/picosha2.h"
#include "Utils.h"
#include "shared_ptr.h"

typedef com::baidu::acu::pie::AsrClient AsrClient;
typedef com::baidu::acu::pie::AsrStream AsrStream;
typedef com::baidu::acu::pie::AudioFragmentResponse AudioFragmentResponse;
typedef com::baidu::acu::pie::AudioFragmentResult AudioFragmentResult;


class  CAsrPortal;
typedef oreka::shared_ptr<CAsrPortal> CAsrPortalRef;


class CAsrPortal {

  private:
    CStdString portal;
    CStdString user;
    CStdString pwd;
    CStdString pid;
    AsrClient client;
    AsrStream* stream {nullptr};
    bool stop { false};
  public:
    void init_asr();
    bool connect_asr_server(CStdString expire_time);
    void send_voice_stream(char* buffer, int i);
    bool get_result(); 
    void uninit_asr();
    bool write_stream(char* buffer, int cnt);
    void read_call_back();
};

#endif

