#ifndef _KAFKA_ASR_H_
#define _KAFKA_ASR_H_


#include "StdString.h"
#include "Utils.h"
#include "rdkafkacpp.h"

class DLL_IMPORT_EXPORT_ORKBASE AsrKafka : public OrkSingleton<AsrKafka> {

  public:
    CStdString portal;
    CStdString topic;
    RdKafka::Producer *producer { nullptr }; 
  public:
    AsrKafka(); 
    bool instance();
    bool push_msg(CStdString& msg);
    bool uninstance(); 
};

#endif
