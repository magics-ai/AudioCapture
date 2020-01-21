#include "BDAsr.h"
#include "LogManager.h"
#include "ConfigManager.h"
#include "kafka_asr.h"


void default_callback(AudioFragmentResponse& resp, 
                      void* data) {
    
    std::stringstream ss;
    if (data) {
        char* tmp = (char*) data;
        CStdString logMsg;
        logMsg.Format(" recived msg %s", tmp);
        LOG4CXX_INFO(LOG.asrLog, logMsg);
    }
    if (resp.type() == com::baidu::acu::pie::FRAGMENT_DATA) {
        AudioFragmentResult *audio_fragment = resp.mutable_audio_fragment();
        /*
        ss << "Receive " << (audio_fragment->completed() ? "completed" : "uncompleted")
           << ", serial_num=" << audio_fragment->serial_num()
           << ", start=" << audio_fragment->start_time()
           << ", end=" << audio_fragment->end_time()
           << ", error_code=" << resp.error_code()
           << ", error_message=" << resp.error_message()
           << ", content=" << audio_fragment->result();*/
        ss << audio_fragment->result();
        std::cout<< "content -" << ss.str() << std::endl;
        AsrKafka* pKafka = AsrKafka::GetInstance();
        CStdString msg(ss.str());
        pKafka->push_msg(msg); 

        CStdString logMsg;
        logMsg.Format(" read content %s",ss.str() /* audio_fragment->result()*/);
        LOG4CXX_INFO(LOG.asrLog, logMsg);
    } else {
        std::stringstream ss;
        ss << "error resp type is=" << resp.type();
        LOG4CXX_INFO(LOG.asrLog, ss.str());
    }
    LOG4CXX_INFO(LOG.asrLog, "default_call_end");
}



void write_to_stream(AsrClient client, AsrStream* stream,
                    char* buffer, int i) {
    int size = client.get_send_package_size();
    CStdString logMsg;
    logMsg.Format(" package_size %d  total_size %d",size, i);
    LOG4CXX_INFO(LOG.asrLog, logMsg);
    
    size_t count = 0;
    int cnt = 0;
    while (i > 0) {
        if (i > size) {
            count = size;
        }
        else {
            count = i;
        }
        logMsg.Format(" send to asr time cnt = %d", cnt++);
        LOG4CXX_INFO(LOG.asrLog, logMsg);
        if (stream->write(buffer, count, false) != 0) {
            LOG4CXX_ERROR(LOG.asrLog, "[error] stream write buffer error");
            break;
        }
        usleep(20*1000);
        if (i < size) {
            LOG4CXX_INFO(LOG.asrLog, " skip write_to_stream loop");
            break;
        }
        else {
            i = i - size;
        }
        buffer = buffer + count;
    }
    LOG4CXX_INFO(LOG.asrLog, " write stream to asr , thread end");
    stream->write(nullptr, 0, true);
//    delete buffer;  
}

void CAsrPortal::init_asr() {
  portal = CONFIG.m_asr_portal;
  pid = CONFIG.m_asr_product_id;
  user = CONFIG.m_asr_user;
  pwd = CONFIG.m_asr_pwd;
}


bool CAsrPortal::connect_asr_server(CStdString expire_time) {
  client.set_app_name("cpp_client");
  client.set_enable_flush_data(true);
  client.set_product_id(pid);
  client.init(portal, 0);
  client.set_user_name(user);
  std::string passwd = pwd;
  std::string str = user + pwd + expire_time;
  std::string token = picosha2::hash256_hex_string(str);
  client.set_token(token);
  client.set_expire_time(expire_time); //expire_time UTC format, 2019-04-25T12:41:16Z
  stream = client.get_stream();
  if (stream) {
    LOG4CXX_INFO(LOG.asrLog, " client get stream success"); 
  } 
  else {
    LOG4CXX_INFO(LOG.asrLog, " client get stream failed");
    return false;
  }
  return true;
}


void CAsrPortal::send_voice_stream(char* buffer, int count) {
    stream->write(buffer, count, false);
}

//
void read_call_back_thread(CAsrPortal* portal, AsrStream* stream) {
  int read_num = 0;
  char tmp[100]; memset(tmp, '\0', 100);
  sprintf(tmp, "audio 0");

  while(!portal->stop) {
    if (stream->read(default_callback, tmp) != 0) {
      break;
    }
    std::stringstream ss;
    ss << "[debug] read stream return " 
                      << read_num++ << "times";
    LOG4CXX_INFO(LOG.asrLog, ss.str())
  }
}


//
void CAsrPortal::start_read_thread() {
    std::thread reader(read_call_back_thread, this, stream);  
    reader.detach();
}

void CAsrPortal::read_call_back() {
    int ret = 0;
    char tmp[100];
    memset(tmp, '\0', 100);
    ret = stream->read(default_callback, tmp);
    if (ret < 0) {
      CStdString logMsg;
      logMsg.Format(" read return failed , ret %d", ret);
      LOG4CXX_INFO(LOG.asrLog, logMsg);
    }
    LOG4CXX_INFO(LOG.asrLog, "read_call_back");
}
/*
void CAsrPortal::send_voice_stream(char* buffer, int i) {

  std::thread reader(read_call_back_thread, stream);  

  //std::thread writer(write_to_stream, client, stream, buffer, i);
  //writer.detach();   
  //int read_num = 1;
  //char tmp[100] = "\0";
  //while(1) {
  //  if (stream->read(default_callback, tmp) != 0) {
  //    break;
  //  }
  //  std::stringstream ss;
  //  ss << "[debug] read stream return " 
  //                    << read_num++ << "times";
  //  LOG4CXX_INFO(LOG.asrLog, ss.str())
  //}
  
  //if (writer.joinable()) {
  //     writer.join();
 // }

}
*/
void CAsrPortal::uninit_asr() {
  stop = true;
  //client.destroy_stream(stream);
  LOG4CXX_INFO(LOG.asrLog, " uninit asr destroy stream");
  //reader.join();
}


